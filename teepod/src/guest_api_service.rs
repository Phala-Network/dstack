use crate::App as AppState;
use anyhow::Result;
use guest_api::{
    proxied_guest_api_server::{ProxiedGuestApiRpc, ProxiedGuestApiServer},
    GuestInfo, Id, ListContainersResponse, NetworkInformation, SystemInfo,
};
use ra_rpc::{CallContext, RpcCall};
use std::ops::Deref;

pub struct GuestApiHandler {
    state: AppState,
}

impl Deref for GuestApiHandler {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl RpcCall<AppState> for GuestApiHandler {
    type PrpcService = ProxiedGuestApiServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(Self {
            state: context.state.clone(),
        })
    }
}

impl ProxiedGuestApiRpc for GuestApiHandler {
    async fn info(self, request: Id) -> Result<GuestInfo> {
        self.tappd_client(&request.id)?
            .info()
            .await
            .map_err(Into::into)
    }

    async fn sys_info(self, request: Id) -> Result<SystemInfo> {
        self.tappd_client(&request.id)?
            .sys_info()
            .await
            .map_err(Into::into)
    }

    async fn network_info(self, request: Id) -> Result<NetworkInformation> {
        self.tappd_client(&request.id)?
            .network_info()
            .await
            .map_err(Into::into)
    }

    async fn list_containers(self, request: Id) -> Result<ListContainersResponse> {
        self.tappd_client(&request.id)?
            .list_containers()
            .await
            .map_err(Into::into)
    }

    async fn shutdown(self, request: Id) -> Result<()> {
        self.tappd_client(&request.id)?
            .shutdown()
            .await
            .map_err(Into::into)
    }
}
