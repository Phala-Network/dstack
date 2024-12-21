use crate::app::App;
use crate::host_api_service::HostApiHandler;
use rocket::{routes, Route};

ra_rpc::declare_prpc_routes!(prpc_post, prpc_get, App, HostApiHandler);

pub fn routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}
