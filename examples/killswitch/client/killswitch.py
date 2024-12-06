from web3 import Web3
from eth_account.signers.local import LocalAccount
from typing import Dict, Any
import time

class Registry:
    def __init__(self, contract_address: str, abi: Dict[str, Any], web3: Web3, app_id: bytes, wallet: LocalAccount, name: str):
        """
        Initialize the Registry client
        
        Args:
            contract_address: Ethereum address of the registry contract
            abi: Contract ABI as a dictionary
            web3: Web3 instance
            app_id: Identifier for the application
            wallet: Wallet for signing transactions
            name: Name of the app
        """
        if isinstance(app_id, str):
            app_id = bytes.fromhex(app_id)
        self.app_id = app_id.ljust(32, b'\0')
        self.web3 = web3
        self.wallet = wallet
        self.name = name
        self.contract = web3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi
        )

    def submit_tx(self, tx: Dict[str, Any]) -> str:
        """
        Submit a transaction
        """
        signed_tx = self.wallet.sign_transaction(tx)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        return tx_hash.hex()
    

    def register(self, tdx_quote: bytes) -> str:
        """
        Register app in the registry
        
        Args:
            tdx_quote: TDX attestation quote

        Returns:
            transaction hash
        """
        tx = self.contract.functions.register(
            self.app_id,
            self.name,
            tdx_quote
        ).build_transaction({
            'from': self.wallet.address,
            'nonce': self.web3.eth.get_transaction_count(self.wallet.address),
        })
        return self.submit_tx(tx)

    def update_name(self, new_name: str) -> str:
        """
        Update app name
        
        Args:
            new_name: New name for the app
            
        Returns:
            transaction hash
        """
        tx = self.contract.functions.updateAppName(
            self.app_id,
            new_name
        ).build_transaction({
            'from': self.wallet.address,
            'nonce': self.web3.eth.get_transaction_count(self.wallet.address),
        })
        return self.submit_tx(tx)
    
    def ban_self(self) -> str:
        """
        Ban the app
        """
        tx = self.contract.functions.banApp(self.app_id).build_transaction({
            'from': self.wallet.address,
            'nonce': self.web3.eth.get_transaction_count(self.wallet.address),
        })
        return self.submit_tx(tx)
    
    def run_killswitch(self) -> str:
        """
        Monitor if this app is banned on the registry. If it is, run shutdown the app.
        """
        while True:
            try:
                if self.check_and_shutdown():
                    break
            except Exception as e:
                print(f"Error checking and shutting down: {e}")
            time.sleep(10)

    def check_and_shutdown(self) -> bool:
        """
        Shutdown the app
        """
        if self.is_banned():
            print("App is banned. Shutting down...")
            # TODO: Implement shutdown logic
            return True
        else:
            print("App is not banned. Continuing...")
            return False

    def get_app_info(self) -> Dict[str, Any]:
        """
        Get app details
        
        Returns:
            Dictionary containing name, isBanned, and owner
        """
        name, is_banned, owner = self.contract.functions.getApp(self.app_id).call()
        
        return {
            'name': name,
            'is_banned': is_banned,
            'owner': owner
        } 
    
    def is_banned(self) -> bool:
        """
        Check if the app is banned
        
        Returns:
            True if banned, False otherwise
        """
        return self.contract.functions.isAppBanned(self.app_id).call()
