# Tappd Client

A Python client for interacting with the Tappd daemon via Unix socket communication.

## Installation

```bash
pip install tappd-client
```

## Usage

```python
from tappd_client import TappdClient

# Initialize the client
client = TappdClient()  # Default socket path: /var/run/tappd.sock
# Or specify custom socket path
client = TappdClient(socket_path='/custom/path/tappd.sock')

# Get TDX quote
# Using binary data
binary_data = b'Hello World'
response = client.tdx_quote(binary_data)

# Using string data
string_data = "Hello World"
response = client.tdx_quote(string_data)
```

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
