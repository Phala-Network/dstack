use crate::dstack_client::GetKeyResponse;
use ethers::signers::LocalWallet;

pub fn to_account(
    get_key_response: &GetKeyResponse
) -> Result<LocalWallet, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = LocalWallet::from_bytes(&key_bytes)?;
    Ok(wallet)
}
