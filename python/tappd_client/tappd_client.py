import requests_unixsocket
import json
import binascii
import hashlib
from urllib.parse import quote


def replay_rtmr(history: list[str]):
    """
    Replay the RTMR history to calculate the final RTMR value.
    """
    INIT_MR= "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    if len(history) == 0:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        # mr = sha384(concat(mr, content))
        # if content is shorter than 48 bytes, pad it with zeros
        content = bytes.fromhex(content)
        if len(content) < 48:
            content = content.ljust(48, b'\0')
        mr = hashlib.sha384(mr + content).digest()
    return mr.hex()


class QuoteResponse:
    def __init__(self, quote, event_log):
        """Initialize a QuoteResponse object with quote data and event log.
        
        Args:
            quote: The quote response from the TDX service
            event_log: List of events containing RTMR measurements
        """
        self.quote = quote
        self.event_log = json.loads(event_log)
    
    def replay_rtmrs(self) -> dict:
        """Replay the RTMR history from the event log to calculate final RTMR values.
        
        Returns:
            dict: Dictionary mapping RTMR indices to their calculated values
        """
        rtmrs = {}
        for idx in range(4):
            history = []
            for event in self.event_log:
                if event.get('imr') == idx:
                    history.append(event['digest'])
            rtmrs[idx] = replay_rtmr(history)
        return rtmrs


class DerivedKey:
    """
    A class to hold the derived key and certificate.
    """
    key: str
    """
    The derived key in pem format.
    """
    certs: list[str]
    """
    The derived certificate chain in pem format.
    """
    def __init__(self, key, certs):
        self.key = key
        self.certs = certs


class TappdClient:
    def __init__(self, socket_path='/var/run/tappd.sock'):
        self.socket_path = socket_path

    def _unix_socket_post(self, endpoint, data):
        """Make a POST request to a Unix socket with the given path and data."""
        session = requests_unixsocket.Session()
        try:
            encoded_path = quote(self.socket_path, safe='')
            socket_url = f"http+unix://{encoded_path}/{endpoint}?json"
            
            response = session.post(socket_url, json=data)
            response.raise_for_status()
            return response.json()
        finally:
            session.close()

    def _rpc_call(self, data, method):
        """Make an RPC call to the tappd service."""
        endpoint = 'prpc/' + method
        try:
            return self._unix_socket_post(endpoint, data)
        except Exception as e:
            print(f"Error: {e}")
            return None

    def tdx_quote(self, report_data: bytes | str) -> QuoteResponse:
        """
        Get TDX quote for the given report data.
        
        Args:
            report_data: Can be either:
                - bytes object
                - regular string
        
        Returns:
            QuoteResponse: An object containing the quote and event log
        """
        if report_data is None:
            raise ValueError("report_data cannot be None")
        if not report_data:  # Check for empty string/bytes
            raise ValueError("report_data cannot be empty")

        if isinstance(report_data, bytes):
            hex_data = binascii.hexlify(report_data).decode('ascii')
        elif isinstance(report_data, str):
            hex_data = report_data.encode('utf-8').hex()
        else:
            raise TypeError("report_data must be either bytes or str")
        
        data = {"report_data": hex_data}
        response = self._rpc_call(data, 'Tappd.TdxQuote')
        return QuoteResponse(response['quote'], response['event_log'])

    def derive_key(self, path: str, subject: str | None = None, alt_names: list[str] | None = None) -> DerivedKey:
        """
        Derive the key and certificate from the given path.
        """
        data = {"path": path}
        data["subject"] = subject or path
        if alt_names:
            data["alt_names"] = alt_names
        response = self._rpc_call(data, 'Tappd.DeriveKey')
        return DerivedKey(response['key'], response['certificate_chain'])

    def info(self) -> dict:
        """
        Get the worker info.
        """
        return self._rpc_call({}, 'Tappd.Info')
