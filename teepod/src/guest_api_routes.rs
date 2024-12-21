use crate::{guest_api_service::GuestApiHandler, App};
use rocket::{routes, Route};

ra_rpc::declare_prpc_routes!(prpc_post, prpc_get, App, GuestApiHandler);

pub fn routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}
