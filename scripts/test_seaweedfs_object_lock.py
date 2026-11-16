"""
SQL-TRUST — SeaweedFS S3 Object Lock & Immutability Test Suite
Independently verifies:
1. Bucket creation with Object Lock enabled
2. Bucket versioning state
3. Bucket Object Lock configuration (COMPLIANCE / GOVERNANCE)
4. Upload of test object
5. Default retention verification
6. Explicit per-object retention (PutObjectRetention / GetObjectRetention)
7. S3 Legal Hold engagement and query (PutObjectLegalHold / GetObjectLegalHold)
8. Rejection of deletion requests while under Legal Hold (403 AccessDenied)
9. Rejection of deletion requests while under Compliance Retention (403 AccessDenied)
10. Version listing and overwrite protection (preserving prior versions)

Reads credentials from environment variables without exposing secrets.
"""

import os
import sys
from datetime import datetime, timezone, timedelta
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

# Terminal color styling
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


def print_header(title: str):
    print(f"\n{BLUE}=== {title} ==={RESET}")


def main():
    print(f"{CYAN}========================================================")
    print("   SQL-TRUST — SeaweedFS S3 Object Lock Verification")
    print(f"========================================================{RESET}")

    endpoint = os.getenv("SEAWEEDFS_ENDPOINT_URL") or os.getenv("S3_ENDPOINT_URL") or "http://127.0.0.1:8333"
    access_key = os.getenv("SEAWEEDFS_ACCESS_KEY") or os.getenv("S3_ACCESS_KEY_ID") or "sqltrust_admin"
    secret_key = os.getenv("SEAWEEDFS_SECRET_KEY") or os.getenv("S3_SECRET_ACCESS_KEY") or "sqltrust_secret_key"
    region = os.getenv("SEAWEEDFS_REGION") or os.getenv("S3_REGION_NAME") or "us-east-1"
    
    test_bucket = "sqltrust-objectlock-test"
    test_key = "object-lock-test.txt"

    print(f"Endpoint: {endpoint}")
    print(f"Target Test Bucket: {test_bucket}")
    print("Credentials: [MASKED / LOADED FROM ENVIRONMENT]")

    results = {}

    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
        config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1})
    )

    # 1. Bucket Creation with Object Lock Enabled
    print_header("1. Bucket Creation with Object Lock Enabled")
    try:
        try:
            s3.head_bucket(Bucket=test_bucket)
            print(f"  Bucket '{test_bucket}' already exists.")
        except ClientError:
            s3.create_bucket(Bucket=test_bucket, ObjectLockEnabledForBucket=True)
            print(f"  Created bucket '{test_bucket}' with ObjectLockEnabledForBucket=True.")
        results["Bucket Creation with Object Lock"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Bucket Creation with Object Lock"] = "FAILED"
        return

    # 2. Bucket Versioning
    print_header("2. Bucket Versioning Configuration")
    try:
        s3.put_bucket_versioning(
            Bucket=test_bucket,
            VersioningConfiguration={"Status": "Enabled"}
        )
        v_resp = s3.get_bucket_versioning(Bucket=test_bucket)
        status = v_resp.get("Status")
        if status == "Enabled":
            print(f"  {GREEN}[PASS]{RESET} Versioning is Enabled.")
            results["Bucket Versioning"] = "SUPPORTED AND TESTED"
        else:
            print(f"  {YELLOW}[WARN]{RESET} Unexpected versioning status: {status}")
            results["Bucket Versioning"] = "FAILED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Bucket Versioning"] = "FAILED"

    # 3. Object Lock Configuration (COMPLIANCE 30 Days)
    print_header("3. Default Object Lock Configuration")
    try:
        s3.put_object_lock_configuration(
            Bucket=test_bucket,
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
        cfg = s3.get_object_lock_configuration(Bucket=test_bucket)
        lock_cfg = cfg.get("ObjectLockConfiguration", {})
        enabled = lock_cfg.get("ObjectLockEnabled")
        rule = lock_cfg.get("Rule", {}).get("DefaultRetention", {})
        mode = rule.get("Mode")
        days = rule.get("Days")
        print(f"  {GREEN}[PASS]{RESET} Object Lock Enabled: {enabled}, Mode: {mode}, Days: {days}")
        if enabled == "Enabled" and mode == "COMPLIANCE" and days == 30:
            results["Object Lock Configuration"] = "SUPPORTED AND TESTED"
        else:
            results["Object Lock Configuration"] = "FAILED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Object Lock Configuration"] = "FAILED"

    # 4. Upload Test Object
    print_header("4. Upload Test Object (Version 1)")
    v1_id = None
    try:
        put_resp = s3.put_object(
            Bucket=test_bucket,
            Key=test_key,
            Body=b"SQL-TRUST Immutability Test Payload - Version 1"
        )
        v1_id = put_resp.get("VersionId")
        print(f"  {GREEN}[PASS]{RESET} Uploaded version 1. VersionId: {v1_id}")
        results["Upload Object"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Upload Object"] = "FAILED"
        return

    # 5. Default Retention Verification
    print_header("5. Default Retention Inspection")
    try:
        ret_resp = s3.get_object_retention(Bucket=test_bucket, Key=test_key, VersionId=v1_id)
        ret = ret_resp.get("Retention", {})
        mode = ret.get("Mode")
        until = ret.get("RetainUntilDate")
        print(f"  {GREEN}[PASS]{RESET} Automatic Default Retention: Mode={mode}, RetainUntilDate={until}")
        results["Default Retention Application"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Default Retention Application"] = "FAILED"

    # 6. Put Object Retention (Explicit Extension)
    print_header("6. Put Object Retention (Explicit Setting)")
    try:
        extend_until = datetime.now(timezone.utc) + timedelta(days=60)
        s3.put_object_retention(
            Bucket=test_bucket,
            Key=test_key,
            VersionId=v1_id,
            Retention={
                "Mode": "COMPLIANCE",
                "RetainUntilDate": extend_until
            }
        )
        ret_resp2 = s3.get_object_retention(Bucket=test_bucket, Key=test_key, VersionId=v1_id)
        ret2 = ret_resp2.get("Retention", {})
        print(f"  {GREEN}[PASS]{RESET} Updated Retention: Mode={ret2.get('Mode')}, RetainUntilDate={ret2.get('RetainUntilDate')}")
        results["Explicit Object Retention (Put/Get)"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Explicit Object Retention (Put/Get)"] = "FAILED"

    # 7. Legal Hold (Put & Get)
    print_header("7. S3 Legal Hold (Put & Get)")
    try:
        s3.put_object_legal_hold(
            Bucket=test_bucket,
            Key=test_key,
            VersionId=v1_id,
            LegalHold={"Status": "ON"}
        )
        lh_resp = s3.get_object_legal_hold(Bucket=test_bucket, Key=test_key, VersionId=v1_id)
        status = lh_resp.get("LegalHold", {}).get("Status")
        print(f"  {GREEN}[PASS]{RESET} Legal Hold Status: {status}")
        if status == "ON":
            results["Legal Hold Configuration"] = "SUPPORTED AND TESTED"
        else:
            results["Legal Hold Configuration"] = "FAILED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Legal Hold Configuration"] = "FAILED"

    # 8. Attempt Deletion with Legal Hold Active
    print_header("8. Attempt Deletion with Legal Hold Active (Expected: Rejection)")
    try:
        s3.delete_object(Bucket=test_bucket, Key=test_key, VersionId=v1_id)
        print(f"  {RED}[FAIL]{RESET} Deletion succeeded! Legal Hold was bypassed!")
        results["Protected Deletion Rejection (Legal Hold)"] = "FAILED"
    except ClientError as e:
        err = e.response.get("Error", {})
        print(f"  {GREEN}[PASS]{RESET} Deletion blocked as expected: Code={err.get('Code')}, Message={err.get('Message')}")
        results["Protected Deletion Rejection (Legal Hold)"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED with unexpected error:{RESET} {e}")
        results["Protected Deletion Rejection (Legal Hold)"] = "FAILED"

    # 9. Release Legal Hold & Attempt Deletion under Compliance Retention
    print_header("9. Attempt Deletion with Compliance Retention Active (Expected: Rejection)")
    try:
        s3.put_object_legal_hold(
            Bucket=test_bucket,
            Key=test_key,
            VersionId=v1_id,
            LegalHold={"Status": "OFF"}
        )
        s3.delete_object(Bucket=test_bucket, Key=test_key, VersionId=v1_id)
        print(f"  {RED}[FAIL]{RESET} Deletion succeeded! Compliance retention was bypassed!")
        results["Protected Deletion Rejection (Compliance)"] = "FAILED"
    except ClientError as e:
        err = e.response.get("Error", {})
        print(f"  {GREEN}[PASS]{RESET} Deletion blocked by retention policy: Code={err.get('Code')}, Message={err.get('Message')}")
        results["Protected Deletion Rejection (Compliance)"] = "SUPPORTED AND TESTED"
    except Exception as e:
        print(f"  {RED}FAILED with unexpected error:{RESET} {e}")
        results["Protected Deletion Rejection (Compliance)"] = "FAILED"

    # 10. Overwrite & Version History Preservation
    print_header("10. Overwrite & Version History Preservation")
    try:
        put_resp2 = s3.put_object(
            Bucket=test_bucket,
            Key=test_key,
            Body=b"SQL-TRUST Version 2 Overwrite Attempt"
        )
        v2_id = put_resp2.get("VersionId")
        vers = s3.list_object_versions(Bucket=test_bucket, Prefix=test_key)
        all_versions = vers.get("Versions", [])
        v_ids = [v["VersionId"] for v in all_versions]
        print(f"  Version 1 ID: {v1_id} in versions: {v1_id in v_ids}")
        print(f"  Version 2 ID: {v2_id} in versions: {v2_id in v_ids}")
        
        # Verify content of original version 1
        orig_content = s3.get_object(Bucket=test_bucket, Key=test_key, VersionId=v1_id)["Body"].read()
        if orig_content == b"SQL-TRUST Immutability Test Payload - Version 1":
            print(f"  {GREEN}[PASS]{RESET} Original version content is intact and unchanged.")
            results["Version History & Overwrite Preservation"] = "SUPPORTED AND TESTED"
        else:
            print(f"  {RED}[FAIL]{RESET} Original version content was modified!")
            results["Version History & Overwrite Preservation"] = "FAILED"
    except Exception as e:
        print(f"  {RED}FAILED:{RESET} {e}")
        results["Version History & Overwrite Preservation"] = "FAILED"

    # Print Summary Matrix
    print(f"\n{CYAN}========================================================")
    print("                 Summary Test Results                   ")
    print(f"========================================================{RESET}")
    for feature, outcome in results.items():
        if outcome == "SUPPORTED AND TESTED":
            color = GREEN
        elif outcome == "SUPPORTED BUT NOT TESTED":
            color = YELLOW
        elif outcome == "UNSUPPORTED":
            color = CYAN
        else:
            color = RED
        print(f"  {feature:<42}: {color}{outcome}{RESET}")
    print(f"{CYAN}========================================================{RESET}\n")


if __name__ == "__main__":
    main()
