# Crypt-KV

A secure key-value store with encryption and AWS S3 storage support. This library provides encrypted storage of key-value pairs with key versioning and flexible storage backends.

## Features

- Encrypted key-value storage using Fernet symmetric encryption
- Merkle tree for data integrity verification
- AWS S3 storage backend
- Flexible storage interface supporting different backends

## Quick Start

```python
import boto3
from crypt_kv import Boto3Db, SimpleKeyProvider, CryptClient

# Initialize S3 client
client = boto3.client('s3', region_name='us-east-1')

# Create storage backend
db = Boto3Db("my-bucket", client)

# Initialize key provider and crypto client
key_provider = SimpleKeyProvider(b"my-root-key")
crypt_client = CryptClient(key_provider, db=db)

# Store encrypted values
crypt_client.set("my-key", b"secret data")

# Retrieve and decrypt values
value = crypt_client.get("my-key")
```

## Examples

### Basic Usage

```python
# Create client with in-memory storage
provider = SimpleKeyProvider(b"test-root-key")
client = CryptClient(provider)

# Store and retrieve values
client.set("key1", b"secret value")
value = client.get("key1")
```

### Persistence Across Sessions

```python
# First session
client1 = CryptClient(provider, db=storage)
client1.set("key1", b"value1")
root_hash = client1.root_hash

# Later session
client2 = CryptClient(provider, root_hash=root_hash, db=storage)
value = client2.get("key1")  # Retrieves original value
```

### AWS S3 Storage

```python
# Initialize S3 backend
s3_client = boto3.client('s3', region_name='us-east-1')
db = Boto3Db("my-bucket", s3_client)

# Create crypto client with S3 storage
client = CryptClient(key_provider, db=db)
```

## Testing

Run tests using pytest:

```bash
pytest test_crypt_kv.py test_s3.py
```
