use anyhow::Result;
use ra_rpc::{Attestation, RpcCall};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    DeriveKeyArgs, DeriveKeyResponse,
};

#[derive(Clone)]
pub struct AppState {}

impl AppState {
    pub fn new() -> Self {
        Self {}
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
