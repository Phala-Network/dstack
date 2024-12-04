from typing import Optional, List, Union
import json
import hashlib
import os
import logging
import base64


from pydantic import BaseModel
import httpx

logger = logging.getLogger('dstack_sdk')


class DeriveKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]

    def toBytes(self, max_length: Optional[int] = None) -> bytes:
        content = self.key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "")
        binary_der = base64.b64decode(content)
        if max_length is None:
            max_length = len(binary_der)
        return binary_der[:max_length]


class TdxQuoteResponse(BaseModel):
    quote: str
    event_log: str


def sha384_hex(input: Union[str, bytes]) -> str:
    if isinstance(input, str):
        input = input.encode()
    return hashlib.sha384(input).hexdigest()


def get_endpoint(endpoint: Union[str, None]):
    if endpoint:
        return endpoint
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}")
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    return "/var/run/tappd.sock"


class BaseClient:
    pass


class TappdClient(BaseClient):
    def __init__(self, endpoint: str = None):
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith('https://'):
            self.transport = httpx.HTTPTransport()
            self.base_url = endpoint
        else:
            self.transport = httpx.HTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    def _send_rpc_request(self, path, payload):
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            response = client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    def derive_key(self, path: str, subject: str) -> DeriveKeyResponse:
        result = self._send_rpc_request("/prpc/Tappd.DeriveKey", {"path": path, "subject": subject})
        return DeriveKeyResponse(**result)

    def tdx_quote(self, report_data: Union[str, bytes]) -> TdxQuoteResponse:
        result = self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": sha384_hex(report_data)})
        return TdxQuoteResponse(**result)


class AsyncTappdClient(BaseClient):
    def __init__(self, endpoint=None):
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith('https://'):
            self.transport = httpx.AsyncHTTPTransport()
            self.base_url = endpoint
        else:
            self.transport = httpx.AsyncHTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    async def _send_rpc_request(self, path, payload):
        async with httpx.AsyncClient(transport=self.transport, base_url=self.base_url) as client:
            response = await client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    async def derive_key(self, path: str, subject: str) -> DeriveKeyResponse:
        result = await self._send_rpc_request("/prpc/Tappd.DeriveKey", {"path": path, "subject": subject})
        return DeriveKeyResponse(**result)

    async def tdx_quote(self, report_data: Union[str, bytes]) -> TdxQuoteResponse:
        result = await self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": sha384_hex(report_data)})
        return TdxQuoteResponse(**result)
