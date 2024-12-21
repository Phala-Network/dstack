use crate::main_service::{Proxy, RpcHandler};
use anyhow::Result;
use rocket::{get, response::content::RawHtml, routes, Route, State};

mod route_index;

#[get("/")]
async fn index(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

ra_rpc::declare_prpc_routes!(prpc_post, prpc_get, Proxy, RpcHandler);

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get]
}
