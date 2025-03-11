import pytest
from solders.keypair import Keypair

from dstack_sdk import AsyncTappdClient, DeriveKeyResponse
from dstack_sdk.solana import to_keypair

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    keypair = to_keypair(result)
    assert isinstance(keypair, Keypair)