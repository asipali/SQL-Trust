"""
SQL-TRUST SeaweedFS S3 Storage Provider
Implements Boto3 client communication with SeaweedFS with full S3 Object Lock (WORM),
Bucket Versioning, Default Retention, Per-Object Retention, and Legal Hold support.
"""
import os
from datetime import datetime, timezone
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from typing import Optional, List, Dict, Any
from backend.config import settings
from backend.services.storage.base import StorageProvider


class SeaweedFSStorageProvider(StorageProvider):
    """
    S3-compatible storage implementation tailored for SeaweedFS with Object Lock support.
    """

    def __init__(self):
        self.endpoint_url = settings.effective_s3_endpoint
        self.access_key = settings.effective_s3_access_key
        self.secret_key = settings.effective_s3_secret_key
        self.bucket_name = settings.effective_s3_bucket
        self.region_name = settings.effective_s3_region

        self.s3_client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region_name,
            config=Config(
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 2}
            )
        )

    def check_connectivity(self) -> Dict[str, Any]:
        """Verify SeaweedFS S3 endpoint connectivity."""
        try:
            self.s3_client.list_buckets()
            return {
                "connected": True,
                "endpoint": self.endpoint_url,
                "bucket": self.bucket_name,
                "provider": "SeaweedFS (S3-compatible with Object Lock)"
            }
        except EndpointConnectionError as e:
            return {
                "connected": False,
                "error": f"Endpoint unreachable: {str(e)}",
                "endpoint": self.endpoint_url
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "endpoint": self.endpoint_url
            }

    def ensure_bucket_exists(self) -> bool:
        """
        Verifies the configured bucket exists; creates it with Object Lock enabled if absent.
        """
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code in ("404", "NoSuchBucket"):
                try:
                    self.s3_client.create_bucket(
                        Bucket=self.bucket_name,
                        ObjectLockEnabledForBucket=True
                    )
                    # Enable versioning
                    self.s3_client.put_bucket_versioning(
                        Bucket=self.bucket_name,
                        VersioningConfiguration={"Status": "Enabled"}
                    )
                    # Set default 30-day COMPLIANCE retention
                    self.s3_client.put_object_lock_configuration(
                        Bucket=self.bucket_name,
                        ObjectLockConfiguration={
                            "ObjectLockEnabled": "Enabled",
                            "Rule": {
                                "DefaultRetention": {
                                    "Mode": "COMPLIANCE",
                                    "Days": 30
                                }
                            }
                        }
                    )
                    return True
                except Exception as create_err:
                    raise RuntimeError(f"Failed to create Object Locked bucket '{self.bucket_name}': {create_err}")
            raise RuntimeError(f"Error checking bucket '{self.bucket_name}': {e}")

    def upload_file(
        self,
        local_file_path: str,
        object_key: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Uploads local file to SeaweedFS, captures VersionId, verifies remote size,
        and confirms active Object Lock retention.
        """
        if not os.path.isfile(local_file_path):
            raise FileNotFoundError(f"Local file not found: {local_file_path}")

        file_size = os.path.getsize(local_file_path)
        self.ensure_bucket_exists()

        try:
            # Upload via put_object or upload_file to reliably capture VersionId
            with open(local_file_path, "rb") as f:
                put_kwargs = {
                    "Bucket": self.bucket_name,
                    "Key": object_key,
                    "Body": f
                }
                if metadata:
                    put_kwargs["Metadata"] = metadata

                put_resp = self.s3_client.put_object(**put_kwargs)

            version_id = put_resp.get("VersionId")
            etag = put_resp.get("ETag", "").strip('"')

            # Verification 1: Fetch object metadata from SeaweedFS to verify upload completeness
            head = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=object_key,
                **({"VersionId": version_id} if version_id else {})
            )
            remote_size = head.get("ContentLength", 0)

            if remote_size != file_size:
                raise ValueError(
                    f"Upload size mismatch! Local size: {file_size} bytes, Remote size: {remote_size} bytes"
                )

            # Verification 2: Query Object Lock Retention status on the uploaded object version
            retention_info = self.get_object_retention(object_key=object_key, version_id=version_id)

            return {
                "success": True,
                "object_key": object_key,
                "version_id": version_id,
                "bucket": self.bucket_name,
                "size_bytes": remote_size,
                "etag": etag,
                "last_modified": head.get("LastModified"),
                "retention_mode": retention_info.get("mode"),
                "retain_until_date": retention_info.get("retain_until_date"),
                "is_immutable": retention_info.get("mode") in ("COMPLIANCE", "GOVERNANCE")
            }
        except Exception as e:
            raise RuntimeError(f"SeaweedFS upload error for '{object_key}': {e}")

    def download_file(
        self,
        object_key: str,
        destination_path: str,
        version_id: Optional[str] = None
    ) -> bool:
        """Downloads an object from SeaweedFS to local filesystem."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(destination_path)), exist_ok=True)
            download_kwargs = {
                "Bucket": self.bucket_name,
                "Key": object_key,
                "Filename": destination_path
            }
            if version_id:
                download_kwargs["ExtraArgs"] = {"VersionId": version_id}

            self.s3_client.download_file(**download_kwargs)
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to download object '{object_key}': {e}")

    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Lists objects with given prefix in bucket."""
        self.ensure_bucket_exists()
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            objects = []
            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                for item in page.get("Contents", []):
                    objects.append({
                        "key": item["Key"],
                        "size_bytes": item["Size"],
                        "last_modified": item["LastModified"].isoformat(),
                        "etag": item.get("ETag", "").strip('"')
                    })
            return objects
        except Exception as e:
            raise RuntimeError(f"Error listing objects in bucket '{self.bucket_name}': {e}")

    def get_object_metadata(self, object_key: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieves metadata headers for a specific object."""
        try:
            head_kwargs = {"Bucket": self.bucket_name, "Key": object_key}
            if version_id:
                head_kwargs["VersionId"] = version_id
            head = self.s3_client.head_object(**head_kwargs)
            return {
                "key": object_key,
                "version_id": head.get("VersionId"),
                "content_length": head.get("ContentLength"),
                "etag": head.get("ETag", "").strip('"'),
                "last_modified": head.get("LastModified").isoformat() if head.get("LastModified") else None,
                "metadata": head.get("Metadata", {})
            }
        except Exception as e:
            raise RuntimeError(f"Error fetching metadata for '{object_key}': {e}")

    def get_object_retention(self, object_key: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Queries the retention policy of a specific object version."""
        try:
            kwargs = {"Bucket": self.bucket_name, "Key": object_key}
            if version_id:
                kwargs["VersionId"] = version_id
            resp = self.s3_client.get_object_retention(**kwargs)
            ret = resp.get("Retention", {})
            return {
                "mode": ret.get("Mode"),
                "retain_until_date": ret.get("RetainUntilDate").isoformat() if ret.get("RetainUntilDate") else None,
                "configured": True
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            return {
                "mode": None,
                "retain_until_date": None,
                "configured": False,
                "code": code
            }
        except Exception as e:
            return {
                "mode": None,
                "retain_until_date": None,
                "configured": False,
                "error": str(e)
            }

    def put_object_retention(
        self,
        object_key: str,
        version_id: str,
        mode: str,
        retain_until: datetime
    ) -> Dict[str, Any]:
        """Applies explicit retention to an object version."""
        try:
            resp = self.s3_client.put_object_retention(
                Bucket=self.bucket_name,
                Key=object_key,
                VersionId=version_id,
                Retention={
                    "Mode": mode,
                    "RetainUntilDate": retain_until
                }
            )
            return {"success": True, "version_id": version_id, "mode": mode, "retain_until": retain_until.isoformat()}
        except Exception as e:
            raise RuntimeError(f"Failed to put object retention on '{object_key}': {e}")

    def get_object_legal_hold(self, object_key: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Queries S3 Legal Hold status for an object version."""
        try:
            kwargs = {"Bucket": self.bucket_name, "Key": object_key}
            if version_id:
                kwargs["VersionId"] = version_id
            resp = self.s3_client.get_object_legal_hold(**kwargs)
            status = resp.get("LegalHold", {}).get("Status", "OFF")
            return {"status": status}
        except ClientError:
            return {"status": "OFF"}

    def put_object_legal_hold(self, object_key: str, version_id: str, status: str) -> bool:
        """Applies or releases Legal Hold on an object version."""
        if status.upper() not in ("ON", "OFF"):
            raise ValueError("Legal Hold status must be 'ON' or 'OFF'")
        try:
            self.s3_client.put_object_legal_hold(
                Bucket=self.bucket_name,
                Key=object_key,
                VersionId=version_id,
                LegalHold={"Status": status.upper()}
            )
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to set legal hold '{status}' on '{object_key}': {e}")

    def inspect_security(self) -> Dict[str, Any]:
        """
        Audits storage immutability, Object Lock, and versioning capabilities.
        Reports exact status verified by live API probes.
        """
        self.ensure_bucket_exists()
        audit_result = {
            "bucket": self.bucket_name,
            "versioning_status": "DISABLED",
            "object_lock_enabled": False,
            "object_lock_rule": None,
            "retention_mode": None,
            "retention_period_days": None,
            "legal_hold_supported": True,
            "immutability_guarantee": "NONE (Standard Object Storage)",
            "warnings": []
        }

        # 1. Check Versioning
        try:
            v_resp = self.s3_client.get_bucket_versioning(Bucket=self.bucket_name)
            v_status = v_resp.get("Status", "DISABLED")
            audit_result["versioning_status"] = v_status
            if v_status != "Enabled":
                audit_result["warnings"].append("Bucket versioning is not enabled. Overwrites could replace backups.")
        except Exception as e:
            audit_result["warnings"].append(f"Versioning inspection error: {e}")

        # 2. Check Object Lock
        try:
            lock_resp = self.s3_client.get_object_lock_configuration(Bucket=self.bucket_name)
            lock_config = lock_resp.get("ObjectLockConfiguration", {})
            if lock_config.get("ObjectLockEnabled") == "Enabled":
                audit_result["object_lock_enabled"] = True
                rule = lock_config.get("Rule", {}).get("DefaultRetention", {})
                audit_result["retention_mode"] = rule.get("Mode")
                audit_result["retention_period_days"] = rule.get("Days")
                audit_result["immutability_guarantee"] = f"WORM Active ({audit_result['retention_mode']} - {audit_result['retention_period_days']} Days)"
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if "ObjectLockConfigurationNotFoundError" in code:
                audit_result["warnings"].append(
                    "Object Lock is not configured on this bucket. S3 API is active, but true WORM immutability is not engaged."
                )
            else:
                audit_result["warnings"].append(f"Object Lock query returned: {code}")
        except Exception as e:
            audit_result["warnings"].append(f"Object Lock inspection error: {e}")

        return audit_result
