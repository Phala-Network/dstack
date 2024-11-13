import pytest
from crypt_kv import SimpleKeyProvider, CryptClient

def test_key_provider():
    # Test key derivation and versioning
    provider = SimpleKeyProvider(b"test-root-key")
    
    # Test default version
    version, key1 = provider.get_key(b"test/path")
    assert version == 0
    assert isinstance(key1, bytes)
    assert len(key1) == 32  # SHA-256 produces 32 byte keys
    
    # Test key derivation is deterministic
    version, key2 = provider.get_key(b"test/path")
    assert key1 == key2
    
    # Test different paths produce different keys
    _, other_key = provider.get_key(b"other/path")
    assert other_key != key1

def test_crypt_client_basic():
    provider = SimpleKeyProvider(b"test-root-key")
    client = CryptClient(provider)
    
    # Test basic set/get
    test_value = b"hello world"
    client.set("test_key", test_value)
    retrieved = client.get("test_key")
    assert retrieved == test_value

def test_crypt_client_multiple_values():
    provider = SimpleKeyProvider(b"test-root-key")
    client = CryptClient(provider)
    
    # Test multiple values
    values = {
        "key1": b"value1",
        "key2": b"value2",
        "key3": b"value3"
    }
    
    for k, v in values.items():
        client.set(k, v)
    
    for k, v in values.items():
        assert client.get(k) == v

def test_persistence():
    provider = SimpleKeyProvider(b"test-root-key")
    db = {}  # Shared db dictionary
    
    # First client sets values
    client1 = CryptClient(provider, db=db)
    client1.set("persistent", b"test data")
    client1.set("key2", b"test data 2")
    client1.set("key3", b"test data 3")
    root_hash = client1.root_hash
    # Second client with same root hash should read same values
    client2 = CryptClient(provider, root_hash=root_hash, db=db)
    assert client2.get("persistent") == b"test data"
    assert client2.get("key2") == b"test data 2"
    assert client2.get("key3") == b"test data 3"

def test_encryption_actually_encrypts():
    provider = SimpleKeyProvider(b"test-root-key")
    client = CryptClient(provider)
    
    test_value = b"secret message"
    client.set("secret", test_value)
    
    # Get raw encrypted value from trie
    packed_data = client.db.get(b"secret")
    assert isinstance(packed_data, bytes)
    
    # Unpack version and encrypted value
    version = int.from_bytes(packed_data[:4], 'big')
    encrypted_value = packed_data[4:]
    
    # Verify the stored data is actually encrypted
    assert version == provider.current_key_version
    assert encrypted_value != test_value
    assert b"secret" not in encrypted_value

def test_invalid_key():
    provider = SimpleKeyProvider(b"test-root-key")
    client = CryptClient(provider)
    
    with pytest.raises(KeyError):
        client.get("nonexistent_key")

def test_delete():
    provider = SimpleKeyProvider(b"test-root-key")
    client = CryptClient(provider)
    
    # Set and verify value exists
    test_value = b"to be deleted"
    client.set("temp", test_value)
    assert client.exists("temp") == True
    
    # Delete and verify it's gone
    client.delete("temp")
    assert client.exists("temp") == False
    
    # Verify get raises KeyError
    with pytest.raises(KeyError):
        client.get("temp")
