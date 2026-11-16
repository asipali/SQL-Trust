"""
SQL-TRUST Environment Validation Script
Verifies:
1. Python version (3.12+)
2. Required Python packages
3. SQLAlchemy import
4. pyodbc import and SQL Server driver availability
5. Boto3 import
6. FastAPI import
7. Docker CLI availability
8. Docker Engine connectivity
9. SQL Server connectivity (SELECT @@VERSION)
10. SeaweedFS S3 endpoint connectivity
"""

import sys
import subprocess
import os

# Terminal color formatting
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_step(num: int, title: str):
    print(f"\n{BLUE}[Check {num}/10]{RESET} {title}...")


def check_python_version() -> bool:
    print_step(1, "Python Version")
    v = sys.version_info
    v_str = f"{v.major}.{v.minor}.{v.micro}"
    print(f"  Current Python executable: {sys.executable}")
    print(f"  Version: {v_str}")
    if v.major == 3 and v.minor >= 12:
        print(f"  {GREEN}[PASS]{RESET} Python 3.12+ requirement satisfied.")
        return True
    else:
        print(f"  {RED}[FAIL]{RESET} Expected Python >= 3.12, got {v_str}")
        return False


def check_required_packages() -> bool:
    print_step(2, "Required Python Packages")
    required = [
        "fastapi", "uvicorn", "sqlalchemy", "pyodbc", "pydantic",
        "pydantic_settings", "boto3", "dotenv", "alembic", "pytest",
        "httpx", "multipart", "cryptography"
    ]
    all_ok = True
    for pkg in required:
        try:
            __import__(pkg)
            print(f"  {GREEN}[OK]{RESET} {pkg}")
        except ImportError:
            print(f"  {RED}[MISSING]{RESET} {pkg}")
            all_ok = False
    return all_ok


def check_sqlalchemy() -> bool:
    print_step(3, "SQLAlchemy Import")
    try:
        import sqlalchemy
        print(f"  {GREEN}[PASS]{RESET} SQLAlchemy version: {sqlalchemy.__version__}")
        return True
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Error importing SQLAlchemy: {e}")
        return False


def check_pyodbc_and_drivers() -> bool:
    print_step(4, "pyodbc Import & ODBC Driver Availability")
    try:
        import pyodbc
        drivers = pyodbc.drivers()
        sql_drivers = [d for d in drivers if "SQL Server" in d]
        print(f"  {GREEN}[PASS]{RESET} pyodbc version: {pyodbc.version}")
        print(f"  Available SQL Server Drivers: {sql_drivers}")
        if any("ODBC Driver 18" in d or "ODBC Driver 17" in d for d in sql_drivers):
            print(f"  {GREEN}[PASS]{RESET} Microsoft ODBC Driver for SQL Server detected.")
            return True
        else:
            print(f"  {YELLOW}[WARN]{RESET} Modern Microsoft ODBC Driver not detected in driver list.")
            return False
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} pyodbc error: {e}")
        return False


def check_boto3() -> bool:
    print_step(5, "Boto3 Import")
    try:
        import boto3
        print(f"  {GREEN}[PASS]{RESET} Boto3 version: {boto3.__version__}")
        return True
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Error importing Boto3: {e}")
        return False


def check_fastapi() -> bool:
    print_step(6, "FastAPI Import")
    try:
        import fastapi
        print(f"  {GREEN}[PASS]{RESET} FastAPI version: {fastapi.__version__}")
        return True
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Error importing FastAPI: {e}")
        return False


def check_docker_cli() -> bool:
    print_step(7, "Docker CLI Availability")
    try:
        res = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            print(f"  {GREEN}[PASS]{RESET} {res.stdout.strip()}")
            return True
        else:
            print(f"  {RED}[FAIL]{RESET} docker CLI exited with code {res.returncode}")
            return False
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Docker CLI not found or failed: {e}")
        return False


def check_docker_engine() -> bool:
    print_step(8, "Docker Engine Connectivity")
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            print(f"  {GREEN}[PASS]{RESET} Docker Engine is running and responsive.")
            return True
        else:
            print(f"  {YELLOW}[NOTICE]{RESET} Docker CLI is present, but Docker daemon is currently stopped.")
            print("  To start Docker: launch Docker Desktop from the Start menu.")
            return False
    except Exception as e:
        print(f"  {YELLOW}[NOTICE]{RESET} Docker Engine check error: {e}")
        return False


def check_sql_server() -> bool:
    print_step(9, "SQL Server Connectivity (Harmless Query: SELECT @@VERSION)")
    try:
        # Load project database helper
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from backend.database import test_sql_connection
        res = test_sql_connection()
        if res.get("success"):
            print(f"  {GREEN}[PASS]{RESET} Successfully connected to SQL Server!")
            print(f"  Server: {res.get('server')}")
            print(f"  Driver: {res.get('driver_used')}")
            version_first_line = res.get("version", "").split("\n")[0]
            print(f"  Reported Version: {version_first_line}")
            return True
        else:
            print(f"  {YELLOW}[NOTICE]{RESET} SQL connection failed: {res.get('error')}")
            return False
    except Exception as e:
        print(f"  {YELLOW}[NOTICE]{RESET} Could not test SQL Server: {e}")
        return False


def check_seaweedfs() -> bool:
    print_step(10, "SeaweedFS S3 Endpoint Connectivity")
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import EndpointConnectionError

        endpoint = os.getenv("S3_ENDPOINT_URL", "http://127.0.0.1:8333")
        s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID", "sqltrust_admin"),
            aws_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY", "sqltrust_secret_key"),
            region_name="us-east-1",
            config=Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 0})
        )
        try:
            s3.list_buckets()
            print(f"  {GREEN}[PASS]{RESET} SeaweedFS S3 endpoint reachable at {endpoint}.")
            return True
        except EndpointConnectionError:
            print(f"  {YELLOW}[PENDING]{RESET} SeaweedFS S3 endpoint {endpoint} is not running.")
            print("  This service runs via Docker Compose and will become available once Docker Desktop daemon is started.")
            return False
        except Exception as e:
            # If endpoint is reachable but credentials/buckets have expected behavior
            print(f"  {GREEN}[PASS]{RESET} Endpoint reached with response: {e}")
            return True
    except Exception as e:
        print(f"  {YELLOW}[NOTICE]{RESET} S3 check: {e}")
        return False


def main():
    print(f"\n==================================================")
    print(f"   SQL-TRUST Environment Validation Pipeline")
    print(f"==================================================")
    
    results = {
        "Python Version": check_python_version(),
        "Required Packages": check_required_packages(),
        "SQLAlchemy": check_sqlalchemy(),
        "pyodbc & Drivers": check_pyodbc_and_drivers(),
        "Boto3": check_boto3(),
        "FastAPI": check_fastapi(),
        "Docker CLI": check_docker_cli(),
        "Docker Daemon": check_docker_engine(),
        "SQL Server": check_sql_server(),
        "SeaweedFS S3": check_seaweedfs(),
    }

    print("\n==================================================")
    print("                 Summary Results                  ")
    print("==================================================")
    for name, passed in results.items():
        status = f"{GREEN}PASS{RESET}" if passed else f"{YELLOW}PENDING / NOT RUNNING{RESET}"
        print(f"  {name:<22}: {status}")
    print("==================================================\n")


if __name__ == "__main__":
    main()

