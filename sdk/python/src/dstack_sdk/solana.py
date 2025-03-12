from solders.keypair import Keypair

from .tappd_client import DeriveKeyResponse

def to_keypair(derive_key_response: DeriveKeyResponse) -> Keypair:
    return Keypair.from_seed(derive_key_response.toBytes(32))