import hashlib
import base64

from typing import Optional
from trie import HexaryTrie
from cryptography.fernet import Fernet


class SimpleKeyProvider:
    """Manages encryption key versioning and derivation.

    Attributes:
        current_key_version: Current version number for key rotation
        root_key: Master key used to derive encryption keys
    """

    current_key_version: int
    root_key: bytes

    def __init__(self, root_key: bytes):
        self.current_key_version = 0
        self.root_key = root_key

    def get_key(self, path: bytes, version: Optional[int] = None) -> tuple[int, bytes]:
        """Gets the encryption key for a given path and version.

        Args:
            path: The path/identifier to derive a key for
            version: Optional key version, defaults to current version

        Returns:
            Tuple of (key version number, derived encryption key)
        """
        version = self.current_key_version if version is None else version
        derived_key = self._derive_key(path, version)
        return (version, derived_key)

    def _derive_key(self, path: bytes, version: int) -> bytes:
        salt = str(version).encode() + b"|" + path
        return hashlib.pbkdf2_hmac(
            'sha256',
            password=self.root_key,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
            dklen=32  # 256-bit key
        )


class DstackKeyProvider(SimpleKeyProvider):
    """Key provider that derives encryption keys from Dstack's key management service."""

    def __init__(self, key_id: str):
        from tappd_client import TappdClient
        self.client = TappdClient()
        pem = self.client.derive_key(key_id).key
        super().__init__(hashlib.sha256(pem.encode()).digest())


class Boto3Db:
    """Database adapter for storing encrypted data in S3 using boto3.

    Provides a dict-like interface for storing and retrieving bytes from S3.
    Keys and values are stored as bytes and base64 encoded for S3 compatibility.

    Attributes:
        bucket: Name of the S3 bucket to store data in
        boto3: Boto3 S3 client instance for making API calls
    """

    def __init__(self, bucket, boto3_client):
        self.bucket = bucket
        self.boto3 = boto3_client

    def __getitem__(self, key: bytes) -> bytes:
        key = base64.urlsafe_b64encode(key).decode()
        return self.boto3.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def __setitem__(self, key: bytes, value: bytes):
        key = base64.urlsafe_b64encode(key).decode()
        self.boto3.put_object(Bucket=self.bucket, Key=key, Body=value)


class FernetCryptor:
    """Encrypts and decrypts data using Fernet symmetric encryption."""

    def encrypt(self, key: bytes, value: bytes) -> bytes:
        f = Fernet(base64.urlsafe_b64encode(key))
        return f.encrypt(value)

    def decrypt(self, key: bytes, value: bytes) -> bytes:
        f = Fernet(base64.urlsafe_b64encode(key))
        return f.decrypt(value)


class CryptClient:
    """Client for encrypting and storing key-value pairs.

    Attributes:
        db: HexaryTrie instance for storing encrypted data
        key_provider: SimpleKeyProvider instance for key management
    """

    db: HexaryTrie
    key_provider: SimpleKeyProvider
    cryptor: FernetCryptor

    def __init__(self, key_provider: SimpleKeyProvider, root_hash=None, db=None, cryptor=None):
        self.key_provider = key_provider
        self.cryptor = cryptor or FernetCryptor()
        if db is None:
            db = {}
        if root_hash is None:
            self.db = HexaryTrie(db=db)
        else:
            self.db = HexaryTrie(db=db, root_hash=root_hash)

    @property
    def root_hash(self) -> bytes:
        return self.db.root_hash

    def _encode_key(self, key: 'str | bytes') -> bytes:
        if isinstance(key, str):
            return key.encode()
        return key

    def get(self, key: str) -> bytes:
        """Get the decrypted value for a key.

        Args:
            key: The key to look up

        Returns:
            The decrypted value as bytes

        Raises:
            KeyError: If the key does not exist
        """
        key = self._encode_key(key)
        if not self.exists(key):
            raise KeyError(f"Key '{key}' not found")
        packed_data = self.db.get(key)
        # Unpack version (first 4 bytes) and encrypted value
        kver = int.from_bytes(packed_data[:4], 'big')
        crypted_value = packed_data[4:]
        (_, crypt_key) = self.key_provider.get_key(key, version=kver)
        decrypted_value = self.cryptor.decrypt(crypt_key, crypted_value)
        return decrypted_value

    def set(self, key: str, value: bytes):
        """Set a key-value pair, encrypting the value.

        Args:
            key: The key to set
            value: The value to encrypt and store
        """
        key = self._encode_key(key)
        (kver, crypt_key) = self.key_provider.get_key(key)
        crypted_value = self.cryptor.encrypt(crypt_key, value)
        # Pack version and encrypted value into single bytes object
        packed_data = kver.to_bytes(4, 'big') + crypted_value
        self.db.set(key, packed_data)

    def exists(self, key: str) -> bool:
        """Check if a key exists.

        Args:
            key: The key to check

        Returns:
            True if the key exists, False otherwise
        """
        key = self._encode_key(key)
        return self.db.exists(key)

    def delete(self, key: str):
        """Delete a key-value pair.

        Args:
            key: The key to delete
        """
        key = self._encode_key(key)
        self.db.delete(key)
