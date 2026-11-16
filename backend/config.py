"""
SQL-TRUST Configuration Module
Loads environment settings from .env file or environment variables.
Supports both Windows-hosted and containerized SQL Server and SeaweedFS instances.
"""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    ENVIRONMENT: str = Field(default="development", description="Runtime environment")
    LOG_LEVEL: str = Field(default="INFO", description="Log level")
    APP_HOST: str = Field(default="127.0.0.1", description="FastAPI host")
    APP_PORT: int = Field(default=8000, description="FastAPI port")

    # SQL Server Control Database & Connection Settings
    SQL_SERVER: str = Field(default=r"localhost\SQLEXPRESS", description="SQL Server hostname/instance")
    SQL_PORT: Optional[int] = Field(default=1764, description="SQL Server TCP port")
    SQL_DATABASE: str = Field(default="SQLTrust_Control", description="Control database name")
    SQL_USER: Optional[str] = Field(default=None, description="SQL Server username")
    SQL_PASSWORD: Optional[str] = Field(default=None, description="SQL Server password")
    SQL_TRUSTED_CONNECTION: str = Field(default="yes", description="Use Windows Authentication")
    SQL_DRIVER: str = Field(default="ODBC Driver 18 for SQL Server", description="ODBC Driver name")

    # Shared Backup Storage Directory (Windows Host and Docker Container paths)
    SQL_BACKUP_DIR: str = Field(
        default=os.path.abspath(r"data\backups"),
        description="Path as seen by SQL Server service"
    )
    BACKUP_LOCAL_DIR: str = Field(
        default=os.path.abspath(r"data\backups"),
        description="Path as seen by backend application"
    )

    # SeaweedFS / S3 Object Storage Settings
    SEAWEEDFS_ENDPOINT_URL: str = Field(default="http://127.0.0.1:8333", description="SeaweedFS S3 API endpoint")
    SEAWEEDFS_ACCESS_KEY: str = Field(default="sqltrust_admin", description="SeaweedFS Access Key")
    SEAWEEDFS_SECRET_KEY: str = Field(default="sqltrust_secret_key", description="SeaweedFS Secret Key")
    SEAWEEDFS_BUCKET: str = Field(default="sqltrust-backups-locked", description="S3 Bucket for immutable backups")
    SEAWEEDFS_REGION: str = Field(default="us-east-1", description="S3 Region")

    # SeaweedFS Read-Only Recovery Identity (Read & List only, zero write/delete)
    SEAWEEDFS_RECOVERY_ACCESS_KEY: str = Field(default="sqltrust_recovery_reader", description="SeaweedFS Read-Only Access Key for recovery")
    SEAWEEDFS_RECOVERY_SECRET_KEY: str = Field(default="sqltrust_reader_secret_key", description="SeaweedFS Read-Only Secret Key for recovery")

    # Recovery Staging Directory
    RECOVERY_STAGING_DIR: str = Field(
        default=os.path.abspath(r"data\recovery_staging"),
        description="Path for staging and verifying backup artifacts prior to restore"
    )

    # Compatibility aliases for S3 generic variables
    S3_ENDPOINT_URL: Optional[str] = Field(default=None, description="Optional S3 Endpoint override")
    S3_ACCESS_KEY_ID: Optional[str] = Field(default=None, description="Optional S3 Access Key override")
    S3_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, description="Optional S3 Secret Key override")
    S3_BUCKET_NAME: Optional[str] = Field(default=None, description="Optional S3 Bucket override")
    S3_REGION_NAME: Optional[str] = Field(default=None, description="Optional S3 Region override")

    # Security
    SECRET_KEY: str = Field(default="sqltrust_development_secret_key_change_in_production", description="App secret")

    @property
    def effective_recovery_s3_access_key(self) -> str:
        return self.SEAWEEDFS_RECOVERY_ACCESS_KEY

    @property
    def effective_recovery_s3_secret_key(self) -> str:
        return self.SEAWEEDFS_RECOVERY_SECRET_KEY

    @property
    def effective_s3_endpoint(self) -> str:
        return self.S3_ENDPOINT_URL or self.SEAWEEDFS_ENDPOINT_URL

    @property
    def effective_s3_access_key(self) -> str:
        return self.S3_ACCESS_KEY_ID or self.SEAWEEDFS_ACCESS_KEY

    @property
    def effective_s3_secret_key(self) -> str:
        return self.S3_SECRET_ACCESS_KEY or self.SEAWEEDFS_SECRET_KEY

    @property
    def effective_s3_bucket(self) -> str:
        return self.S3_BUCKET_NAME or self.SEAWEEDFS_BUCKET

    @property
    def effective_s3_region(self) -> str:
        return self.S3_REGION_NAME or self.SEAWEEDFS_REGION


settings = Settings()
