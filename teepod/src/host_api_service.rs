use anyhow::Result;
use host_api::{
    host_api_server::{HostApiRpc, HostApiServer},
    HostInfo,
};
use ra_rpc::{Attestation, RpcCall};

use crate::app::App;

pub struct HostApiHandler {
    app: App,
}

impl RpcCall<App> for HostApiHandler {
    type PrpcService = HostApiServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        HostApiServer::new(self)
    }

    fn construct(state: &App, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { app: state.clone() })
    }
}

impl HostApiRpc for HostApiHandler {
    async fn info(self) -> Result<HostInfo> {
        let host_info = HostInfo {
            name: "Teepod".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        Ok(host_info)
    }
}
