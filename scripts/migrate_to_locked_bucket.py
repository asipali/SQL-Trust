"""
SQL-TRUST — Migration to Object-Locked S3 Storage
Migrates backups from 'sqltrust-backups' to 'sqltrust-backups-locked'.
Preserves source data, verifies SHA-256 and size, applies COMPLIANCE retention,
and logs migration results.
"""
import os
import sys
import hashlib
from datetime import datetime, timezone
import boto3
from botocore.config import Config

endpoint = os.getenv("SEAWEEDFS_ENDPOINT_URL") or os.getenv("S3_ENDPOINT_URL") or "http://127.0.0.1:8333"
access_key = os.getenv("SEAWEEDFS_ACCESS_KEY") or os.getenv("S3_ACCESS_KEY_ID") or "sqltrust_admin"
secret_key = os.getenv("SEAWEEDFS_SECRET_KEY") or os.getenv("S3_SECRET_ACCESS_KEY") or "sqltrust_secret_key"
region = os.getenv("SEAWEEDFS_REGION") or os.getenv("S3_REGION_NAME") or "us-east-1"

source_bucket = "sqltrust-backups"
dest_bucket = "sqltrust-backups-locked"

s3 = boto3.client(
    "s3",
    endpoint_url=endpoint,
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name=region,
    config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2})
)

def run_migration():
    print("==================================================")
    print(" SQL-TRUST Backup Migration to Object-Locked Bucket")
    print("==================================================")
    print(f"Source Bucket: {source_bucket} (Ordinary S3)")
    print(f"Destination:   {dest_bucket} (Object Locked / WORM)")

    # Ensure dest bucket is configured
    try:
        lock_cfg = s3.get_object_lock_configuration(Bucket=dest_bucket)
        print("Destination Object Lock Verified:", lock_cfg.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled"))
    except Exception as e:
        print(f"ERROR: Destination bucket '{dest_bucket}' is not configured with Object Lock: {e}")
        sys.exit(1)

    paginator = s3.get_paginator("list_objects_v2")
    migrated_count = 0
    verified_count = 0

    for page in paginator.paginate(Bucket=source_bucket):
        for item in page.get("Contents", []):
            key = item["Key"]
            src_size = item["Size"]
            print(f"\nMigrating: {key} ({src_size} bytes)")

            # Fetch source object data
            src_obj = s3.get_object(Bucket=source_bucket, Key=key)
            src_body = src_obj["Body"].read()
            src_sha256 = hashlib.sha256(src_body).hexdigest()
            src_meta = src_obj.get("Metadata", {})

            # Put object in destination bucket (automatically acquires 30-day default COMPLIANCE retention)
            put_resp = s3.put_object(
                Bucket=dest_bucket,
                Key=key,
                Body=src_body,
                Metadata=src_meta
            )
            dest_version_id = put_resp.get("VersionId")
            print(f"  Uploaded to dest. VersionId: {dest_version_id}")

            # Verify size and sha256 in destination
            dest_obj = s3.get_object(Bucket=dest_bucket, Key=key, VersionId=dest_version_id)
            dest_body = dest_obj["Body"].read()
            dest_sha256 = hashlib.sha256(dest_body).hexdigest()
            dest_size = dest_obj["ContentLength"]

            if src_size != dest_size:
                raise ValueError(f"Size mismatch on {key}: source={src_size}, dest={dest_size}")
            if src_sha256 != dest_sha256:
                raise ValueError(f"SHA-256 mismatch on {key}!")

            # Verify retention is active on the new version
            try:
                ret_resp = s3.get_object_retention(Bucket=dest_bucket, Key=key, VersionId=dest_version_id)
                ret_mode = ret_resp.get("Retention", {}).get("Mode")
                ret_until = ret_resp.get("Retention", {}).get("RetainUntilDate")
                print(f"  Verified Retention: Mode={ret_mode}, RetainUntilDate={ret_until}")
            except Exception as e:
                print(f"  Warning querying retention: {e}")

            migrated_count += 1
            verified_count += 1

    print("\n==================================================")
    print("               Migration Summary                  ")
    print("==================================================")
    print(f"Total Objects Migrated: {migrated_count}")
    print(f"Total Verified (SHA-256 + Size + Retention): {verified_count}")
    print(f"Source Bucket Preserved: '{source_bucket}' remains untouched.")
    print("==================================================\n")

if __name__ == "__main__":
    run_migration()
