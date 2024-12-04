import pytest
from dstack_sdk import TappdClient, AsyncTappdClient, DeriveKeyResponse, TdxQuoteResponse

# endpoint = '../../tappd.sock'
endpoint = 'http://127.0.0.1:8090'

def test_sync_client_derive_key():
    client = TappdClient(endpoint)
    result = client.derive_key('/', 'test')
    assert isinstance(result, DeriveKeyResponse)
    asBytes = result.toBytes()
    assert isinstance(asBytes, bytes)
    asBytes = result.toBytes(32)
    assert isinstance(asBytes, bytes)
    assert len(asBytes) == 32

def test_sync_client_tdx_quote():
    client = TappdClient(endpoint)
    result = client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient(endpoint)
    result = await client.derive_key('/', 'test')
    assert isinstance(result, DeriveKeyResponse)

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient(endpoint)
    result = await client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)
