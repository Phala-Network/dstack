use anyhow::{bail, Result};
use host_api::{
    host_api_server::{HostApiRpc, HostApiServer},
    HostInfo, Notification,
};
use ra_rpc::{CallContext, RemoteEndpoint, RpcCall};
use rocket_vsock_listener::VsockEndpoint;

use crate::app::App;

pub struct HostApiHandler {
    endpoint: VsockEndpoint,
    app: App,
}

impl RpcCall<App> for HostApiHandler {
    type PrpcService = HostApiServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        HostApiServer::new(self)
    }

    fn construct(context: CallContext<'_, App>) -> Result<Self>
    where
        Self: Sized,
    {
        let Some(RemoteEndpoint::Vsock { cid, port }) = context.remote_endpoint else {
            bail!("invalid remote endpoint: {:?}", context.remote_endpoint);
        };
        Ok(Self {
            endpoint: VsockEndpoint { cid, port },
            app: context.state.clone(),
        })
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

    async fn notify(self, request: Notification) -> Result<()> {
        self.app
            .vm_event_report(self.endpoint.cid, &request.event, &request.message)
    }
}
