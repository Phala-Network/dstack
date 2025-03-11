import pytest
from eth_account.signers.local import LocalAccount

from dstack_sdk import AsyncTappdClient, DeriveKeyResponse
from dstack_sdk.ethereum import to_account

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    account = to_account(result)
    assert isinstance(account, LocalAccount)