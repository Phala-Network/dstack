# DStack SDK

This SDK provides a Python client for communicating with the Tappd server, which is available inside DStack.

## Installation

```bash
pip install dstack-sdk
```

## Basic Usage

```python
from dstack_sdk import TappdClient, AsyncTappdClient

# Synchronous client
client = TappdClient()

# Caution: You don't need to do this most of the time.
http_client = TappdClient('http://localhost:8000')

# Asynchronous client
async_client = AsyncTappdClient()

# Get the information of the Base Image.
info = client.info()  # or await async_client.info()
print(info.app_id)  # Application ID
print(info.tcb_info.mrtd)  # Access TCB info directly
print(info.tcb_info.event_log[0].event)  # Access event log entries

# Derive a key with optional path and subject
key_result = client.derive_key('<unique-id>')  # or await async_client.derive_key('<unique-id>')
print(key_result.key)  # X.509 private key in PEM format
print(key_result.certificate_chain)  # Certificate chain
key_bytes = key_result.toBytes()  # Get key as bytes

# Generate TDX quote
quote_result = client.tdx_quote('some-data', 'sha256')  # or await async_client.tdx_quote('some-data', 'sha256')
print(quote_result.quote)  # TDX quote in hex format
print(quote_result.event_log)  # Event log
rtmrs = quote_result.replay_rtmrs()  # Replay RTMRs
```

For `tdx_quote`, it supports a range of hash algorithms, including:

- `sha256`: SHA-256 hash algorithm
- `sha384`: SHA-384 hash algorithm 
- `sha512`: SHA-512 hash algorithm
- `sha3-256`: SHA3-256 hash algorithm
- `sha3-384`: SHA3-384 hash algorithm
- `sha3-512`: SHA3-512 hash algorithm
- `keccak256`: Keccak-256 hash algorithm
- `keccak384`: Keccak-384 hash algorithm
- `keccak512`: Keccak-512 hash algorithm
- `raw`: No hashing, use raw data (must be <= 64 bytes)

## Web3 Integration

The SDK provides integration with various blockchain ecosystems. You need to install the SDK with the appropriate optional dependencies:

```bash
# For Ethereum support
pip install "dstack-sdk[eth]"

# For Solana support
pip install "dstack-sdk[sol]"

# For both
pip install "dstack-sdk[all]"
```

### Ethereum

You can use derived keys with the built-in Ethereum integration:

```python
from dstack_sdk import TappdClient
from dstack_sdk.ethereum import to_account

# Derive a key
client = TappdClient()
key_result = client.derive_key('eth-account')

# Convert to Ethereum account
account = to_account(key_result)
print(f"Ethereum address: {account.address}")

# Use with Web3
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY'))
# Sign transactions, etc.
```

### Solana

For Solana integration, use the built-in helper:

```python
from dstack_sdk import TappdClient
from dstack_sdk.solana import to_keypair

# Derive a key
client = TappdClient()
key_result = client.derive_key('solana-account')

# Convert to Solana keypair
keypair = to_keypair(key_result)
print(f"Solana public key: {keypair.pubkey()}")

# Use with Solana transactions
# ... (sign transactions, etc.)
```

## API Reference

### TappdClient and AsyncTappdClient

#### Constructor
```python
TappdClient(endpoint: str | None = None)
AsyncTappdClient(endpoint: str | None = None)
```
- `endpoint`: Unix socket path or HTTP(S) URL. Defaults to '/var/run/tappd.sock'.
- Uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

NOTE: Leave it empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
```

For local development without TDX devices, you can use the simulator available for download here:

https://github.com/Leechael/tappd-simulator/releases

#### Methods

##### `derive_key(path: str | None = None, subject: str | None = None, alt_names: List[str] | None = None) -> DeriveKeyResponse`

Derives a key for the given path and subject.

**NOTE: Only the `path` affects the derived result. `subject` & `alt_names` are for the generated certificate and do not affect the derived result.**

- `path`: Optional path for key derivation
- `subject`: Optional subject name (defaults to path)
- `alt_names`: Optional alternative names for the certificate
- Returns: `DeriveKeyResponse` containing key and certificate chain

##### `tdx_quote(report_data: str | bytes, hash_algorithm: QuoteHashAlgorithms = '') -> TdxQuoteResponse`

Generates a TDX quote. The quote is returned in hex format, and you can paste your quote into https://proof.t16z.com/ to get the attestation report.

- `report_data`: Data to include in the quote
- `hash_algorithm`: Hash algorithm to use (sha256, sha384, sha512, etc.)
- Returns: `TdxQuoteResponse` containing quote and event log

##### `info() -> TappdInfoResponse`
Retrieves server information.
- Returns: Information about the Tappd instance, including TCB info and event logs

### Types

```python
class DeriveKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]
    
    def toBytes(self, max_length: Optional[int] = None) -> bytes: ...

QuoteHashAlgorithms = Literal[
    'sha256', 'sha384', 'sha512',
    'sha3-256', 'sha3-384', 'sha3-512',
    'keccak256', 'keccak384', 'keccak512',
    'raw'
]

class TdxQuoteResponse(BaseModel):
    quote: str
    event_log: str
    
    def replay_rtmrs(self) -> Dict[int, str]: ...

class EventLog(BaseModel):
    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str

class TcbInfo(BaseModel):
    mrtd: str
    rootfs_hash: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    event_log: List[EventLog]

class TappdInfoResponse(BaseModel):
    app_id: str
    instance_id: str
    app_cert: str
    tcb_info: TcbInfo
    app_name: str
    public_logs: bool
    public_sysinfo: bool
```

## Development

We use [PDM](https://pdm-project.org/en/latest/) for local development and creating an isolated environment.

Just run the following command to initiate development:

```bash
pdm install -d
```

Running test cases with local simulator via `/tmp/tappd.sock`:

```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock pdm run pytest
```

## License

Apache License

