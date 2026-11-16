"""
SQL-TRUST Abstract Storage Provider Interface
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any


class StorageProvider(ABC):
    """
    Abstract interface for object storage backends.
    """

    @abstractmethod
    def check_connectivity(self) -> Dict[str, Any]:
        """Verify storage backend availability."""
        pass

    @abstractmethod
    def ensure_bucket_exists(self) -> bool:
        """Verify that the target storage bucket exists, creating it if absent."""
        pass

    @abstractmethod
    def upload_file(
        self,
        local_file_path: str,
        object_key: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Uploads a file to object storage and verifies the uploaded object.
        Returns upload details including size, etag, and object_key.
        """
        pass

    @abstractmethod
    def download_file(
        self,
        object_key: str,
        destination_path: str
    ) -> bool:
        """Downloads an object from storage to a local file path."""
        pass

    @abstractmethod
    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Lists objects within the target bucket matching the given prefix."""
        pass

    @abstractmethod
    def get_object_metadata(self, object_key: str) -> Dict[str, Any]:
        """Retrieves metadata and headers for a stored object."""
        pass

    @abstractmethod
    def inspect_security(self) -> Dict[str, Any]:
        """
        Audits storage security posture including Object Lock, Versioning,
        Retention policies, and Legal Hold configurations.
        """
        pass
