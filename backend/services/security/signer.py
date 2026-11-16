"""
SQL-TRUST Cryptographic Evidence Signing & Verification Service
Module 2: Security Monitoring Engine
Uses Ed25519 high-speed public-key cryptography to sign deterministic evidence manifests.
"""
import os
import json
import base64
from pathlib import Path
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class ManifestSigner:
    """
    Manages asymmetric keypair generation, deterministic manifest signing,
    and public-key signature verification for forensic evidence artifacts.
    """

    def __init__(self, key_dir: str = None):
        self.key_dir = Path(key_dir or os.path.abspath(r"data\keys"))
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.private_key_path = self.key_dir / "sqltrust_signing_ed25519.key"
        self.public_key_path = self.key_dir / "sqltrust_signing_ed25519.pub"
        self._ensure_keypair()

    def _ensure_keypair(self) -> None:
        """Loads existing Ed25519 keypair or generates a new dedicated pair."""
        if not self.private_key_path.exists() or not self.public_key_path.exists():
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Save private key (unencrypted PEM format for local daemon operation)
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_key_path.write_bytes(priv_bytes)

            # Save public key
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key_path.write_bytes(pub_bytes)

    def get_public_key_pem(self) -> str:
        """Returns the public key in PEM format."""
        return self.public_key_path.read_text(encoding="utf-8")

    def canonicalize(self, data: Dict[str, Any]) -> bytes:
        """Serializes dictionary to deterministic canonical UTF-8 JSON bytes."""
        def default_serializer(o):
            if hasattr(o, "isoformat"):
                return o.isoformat()
            return str(o)
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=default_serializer).encode("utf-8")

    def sign_manifest(self, manifest_data: Dict[str, Any]) -> str:
        """
        Signs canonicalized manifest data using the Ed25519 private key.
        Returns URL-safe Base64 encoded signature.
        """
        priv_bytes = self.private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)
        canonical_bytes = self.canonicalize(manifest_data)
        signature = private_key.sign(canonical_bytes)
        return base64.b64encode(signature).decode("utf-8")

    def verify_manifest(self, manifest_data: Dict[str, Any], signature_b64: str, public_key_pem: str = None) -> bool:
        """
        Verifies manifest signature against the public key.
        Automatically ignores 'signature' key inside manifest_data if present.
        Returns True if signature is authentic, False otherwise.
        """
        try:
            pub_pem = public_key_pem or self.get_public_key_pem()
            public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            signature = base64.b64decode(signature_b64.encode("utf-8"))
            
            # Clean copy excluding signature keys
            clean_manifest = {k: v for k, v in manifest_data.items() if k not in ("signature", "digital_signature")}
            canonical_bytes = self.canonicalize(clean_manifest)
            public_key.verify(signature, canonical_bytes)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False


signer = ManifestSigner()
