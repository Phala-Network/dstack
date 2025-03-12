from eth_account import Account

from .tappd_client import DeriveKeyResponse

def to_account(derive_key_response: DeriveKeyResponse) -> Account:
    return Account.from_key(derive_key_response.toBytes(32))
