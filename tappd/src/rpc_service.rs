use std::sync::Arc;

use anyhow::{Context, Result};
use ra_rpc::{Attestation, RpcCall};
use ra_tls::{cert::CertRequest, rcgen};
use rcgen::{Certificate, KeyPair};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    DeriveKeyArgs, DeriveKeyResponse,
};
use fs_err as fs;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    key: KeyPair,
    cert: String,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self> {
        let pem_key = fs::read_to_string(&config.key_file).context("Failed to read key file")?;
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert = fs::read_to_string(&config.cert_file).context("Failed to read cert file")?;
        Ok(Self {
            inner: Arc::new(AppStateInner { key, cert }),
        })
    }
}

pub struct RpcHandler {
    state: AppState,
}

impl TappdRpc for RpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        Ok(DeriveKeyResponse {
            key: vec![1; 32],
            certificate: vec![1; 1024],
        })
    }
}

impl RpcCall<AppState> for RpcHandler {
    type PrpcService = TappdServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TappdServer::new(self)
    }

    fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <TappdServer<RpcHandler>>::supported_methods()
}
