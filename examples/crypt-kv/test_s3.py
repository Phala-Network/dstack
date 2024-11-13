import boto3
from moto import mock_aws
from crypt_kv import Boto3Db, SimpleKeyProvider, CryptClient


@mock_aws
def test_s3_put():
    conn = boto3.resource("s3", region_name="us-east-1")
    conn.create_bucket(Bucket="mybucket")

    client = boto3.client("s3", region_name="us-east-1")
    db = Boto3Db("mybucket", client)
    key_provider = SimpleKeyProvider(b"keyring1")
    crypt_client = CryptClient(key_provider, db=db)

    # set some values
    crypt_client.set(b"TEE", b"is awesome")
    crypt_client.set(b"foo", b"bar")

    # list objects
    response = client.list_objects_v2(Bucket="mybucket")
    n_keys = len([_ for _ in response["Contents"]])
    assert n_keys == 4

    # Create a new client instance
    root_hash = crypt_client.root_hash
    client = boto3.client("s3", region_name="us-east-1")
    db = Boto3Db("mybucket", client)
    crypt_client2 = CryptClient(SimpleKeyProvider(b"keyring1"), root_hash=root_hash, db=db)

    # get the set values
    val_tee = crypt_client2.get(b"TEE")
    assert val_tee == b"is awesome"
    val_foo = crypt_client2.get(b"foo")
    assert val_foo == b"bar"
    print(f"tee={val_tee}")
    print(f"foo={val_foo}")

test_s3_put()
