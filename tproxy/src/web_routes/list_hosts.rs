use crate::{
    main_service::{AppState, RpcHandler},
    models::CvmList,
};
use anyhow::Context;
use ra_rpc::RpcCall;
use rinja::Template as _;
use rocket::{response::content::RawHtml as Html, State};
use tproxy_rpc::tproxy_server::TproxyRpc;

pub async fn list_hosts(state: &State<AppState>) -> anyhow::Result<Html<String>> {
    let rpc_handler =
        RpcHandler::construct(state, None).context("Failed to construct RpcHandler")?;
    let response = rpc_handler.list().await.context("Failed to list hosts")?;
    let model = CvmList {
        hosts: &response.hosts,
    };
    let html = model.render().context("Failed to render template")?;
    Ok(Html(html))
}
