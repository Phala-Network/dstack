#!/usr/bin/env python3
import os
from typing import Optional, Tuple
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3
import uvicorn
import argparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="DStack KMS Ethereum Backend")

KMS_CONTRACT_ABI = '''
[{
    "inputs": [{
        "components": [
            {"name": "appId", "type": "address"},
            {"name": "composeHash", "type": "bytes32"},
            {"name": "instanceId", "type": "address"},
            {"name": "deviceId", "type": "bytes32"},
            {"name": "mrEnclave", "type": "bytes32"},
            {"name": "mrImage", "type": "bytes32"}
        ],
        "name": "bootInfo",
        "type": "tuple"
    }],
    "name": "isAppAllowed",
    "outputs": [
        {"name": "allowed", "type": "bool"},
        {"name": "reason", "type": "string"}
    ],
    "stateMutability": "view",
    "type": "function"
}, {
    "inputs": [],
    "name": "kmsAppId",
    "outputs": [{"name": "appId", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
}, {
    "inputs": [{"name": "appId", "type": "address"}],
    "name": "appController",
    "outputs": [{"name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
}, ]
'''

APP_CONTRACT_ABI = '''
[{
    "inputs": [{
        "components": [
            {"name": "appId", "type": "address"},
            {"name": "composeHash", "type": "bytes32"},
            {"name": "instanceId", "type": "address"},
            {"name": "deviceId", "type": "bytes32"},
            {"name": "mrEnclave", "type": "bytes32"},
            {"name": "mrImage", "type": "bytes32"}
        ],
        "name": "bootInfo",
        "type": "tuple"
    }],
    "name": "isAppAllowed",
    "outputs": [
        {"name": "allowed", "type": "bool"},
        {"name": "reason", "type": "string"}
    ],
    "stateMutability": "view",
    "type": "function"
}]
'''

class BootInfo(BaseModel):
    mr_enclave: str = Field(..., description="MR Enclave measurement")
    mr_image: str = Field(..., description="MR Image measurement")
    app_id: str = Field(..., description="Application ID")
    compose_hash: str = Field(..., description="Compose hash")
    instance_id: str = Field(..., description="Instance ID")
    device_id: str = Field(..., description="Device ID")

class BootResponse(BaseModel):
    is_allowed: bool
    reason: str

class EthereumBackend:
    def __init__(self, rpc_url: str, kms_contract_addr: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Initialize KMS contract
        self.kms_contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(kms_contract_addr),
            abi=KMS_CONTRACT_ABI
        )

    def decode_hex32(self, hex_str: str) -> bytes:
        """Convert hex string to 32 bytes."""
        hex_str = hex_str.removeprefix("0x")
        return bytes.fromhex(hex_str.zfill(64))

    async def get_app_controller(self, app_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Get AppAuth contract address from KMS contract."""
        try:
            app_id_checksum = Web3.to_checksum_address(app_id)
            # Run the synchronous contract call in a thread pool
            controller = await self.w3.eth.coro_call(
                self.kms_contract.functions.appController(app_id_checksum)
            )
            if controller == "0x" + "0" * 40:
                return None, "No controller set for app"
                
            return controller, None
            
        except Exception as e:
            return None, f"Error checking app registration: {str(e)}"

    async def check_boot(self, boot_info: BootInfo, is_kms: bool) -> BootResponse:
        try:
            # if is_kms, we need to ensure the App ID is the KMS App ID in the contract
            if is_kms:
                kms_app_id = await self.w3.eth.coro_call(
                    self.kms_contract.functions.kmsAppId()
                )
                if boot_info.app_id != kms_app_id:
                    return BootResponse(is_allowed=False, reason="App ID does not match KMS app ID")

            # Create boot info tuple for contract call
            boot_info_tuple = (
                Web3.to_checksum_address(boot_info.app_id),
                self.decode_hex32(boot_info.compose_hash),
                Web3.to_checksum_address(boot_info.instance_id),
                self.decode_hex32(boot_info.device_id),
                self.decode_hex32(boot_info.mr_enclave),
                self.decode_hex32(boot_info.mr_image)
            )

            # First check with KmsAuth if the app and measurements are allowed
            kms_allowed, kms_reason = await self.w3.eth.coro_call(
                self.kms_contract.functions.isAppAllowed(boot_info_tuple)
            )

            if not kms_allowed:
                return BootResponse(is_allowed=False, reason=f"KMS check failed: {kms_reason}")

            # Then check if app is registered and get AppAuth contract
            controller_addr, error = await self.get_app_controller(boot_info.app_id)
            if not controller_addr:
                return BootResponse(is_allowed=False, reason=error)

            # Initialize AppAuth contract
            app_auth = self.w3.eth.contract(
                address=Web3.to_checksum_address(controller_addr),
                abi=APP_CONTRACT_ABI
            )

            # Finally check with AppAuth contract
            is_allowed, reason = await self.w3.eth.coro_call(
                app_auth.functions.isAppAllowed(boot_info_tuple)
            )

            return BootResponse(is_allowed=is_allowed, reason=reason)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# Global backend instance
backend: Optional[EthereumBackend] = None


@app.post("/bootAuth/app", response_model=BootResponse)
async def check_boot_app(boot_info: BootInfo):
    if backend is None:
        raise HTTPException(status_code=500, detail="Backend not initialized")
    return await backend.check_boot(boot_info, is_kms=False)


@app.post("/bootAuth/kms", response_model=BootResponse)
async def check_boot_kms(boot_info: BootInfo):
    if backend is None:
        raise HTTPException(status_code=500, detail="Backend not initialized")
    return await backend.check_boot(boot_info, is_kms=True)


def main():
    global backend

    parser = argparse.ArgumentParser(description="DStack KMS Ethereum Backend")
    parser.add_argument("--eth-rpc-url", default=os.getenv("ETH_RPC_URL"), help="Ethereum RPC URL")
    parser.add_argument("--kms-contract", default=os.getenv("KMS_CONTRACT"), help="KMS contract address")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=3000, help="Listen port")

    args = parser.parse_args()

    if not args.eth_rpc_url:
        print("Error: ETH_RPC_URL not set")
        return
    if not args.kms_contract:
        print("Error: KMS_CONTRACT not set")
        return

    backend = EthereumBackend(args.eth_rpc_url, args.kms_contract)
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
