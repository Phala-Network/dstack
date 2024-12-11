import hashlib
import pytest

from evidence_api.tdx.quote import TdxQuote

from dstack_sdk import TappdClient, AsyncTappdClient, DeriveKeyResponse, TdxQuoteResponse

def test_sync_client_derive_key():
    client = TappdClient()
    result = client.derive_key()
    assert isinstance(result, DeriveKeyResponse)
    asBytes = result.toBytes()
    assert isinstance(asBytes, bytes)
    asBytes = result.toBytes(32)
    assert isinstance(asBytes, bytes)
    assert len(asBytes) == 32

def test_sync_client_tdx_quote():
    client = TappdClient()
    result = client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient()
    result = await client.derive_key()
    assert isinstance(result, DeriveKeyResponse)

@pytest.mark.asyncio
async def test_async_client_tdx_quote():
    client = AsyncTappdClient()
    result = await client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)

@pytest.mark.asyncio
async def test_replay_rtmr():
    client = AsyncTappdClient()
    result = await client.tdx_quote('test')
    # TODO evidence_api is a bit out-of-date, we need an up-to-date implementation.
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    rtmrs = result.replay_rtmrs()
    assert rtmrs[0] == tdxQuote.body.rtmr0.hex()
    assert rtmrs[1] == tdxQuote.body.rtmr1.hex()
    assert rtmrs[2] == tdxQuote.body.rtmr2.hex()
    assert rtmrs[3] == tdxQuote.body.rtmr3.hex()

@pytest.mark.asyncio
async def test_tdx_quote_raw_hash_error():
    with pytest.raises(ValueError) as excinfo:
        client = AsyncTappdClient()
        await client.tdx_quote('0' * 65, 'raw')
    assert '64 characters' in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        client = AsyncTappdClient()
        await client.tdx_quote(b'0' * 129, 'raw')
    assert '128 bytes' in str(excinfo.value)

@pytest.mark.asyncio
async def test_report_data():
    reportdata = 'test'
    client = AsyncTappdClient()
    result = await client.tdx_quote(reportdata)
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    assert hashlib.sha512(b"app-data:" + reportdata.encode("utf8")).hexdigest() == tdxQuote.body.reportdata.hex()
    # #2
    result = await client.tdx_quote(reportdata, 'raw')
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    print(tdxQuote.body.reportdata.lstrip(b'\x00') == reportdata.encode('utf8'))
