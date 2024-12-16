use crate::app::App;
use crate::host_api_service::HostApiHandler;
use fs_err as fs;
use ra_rpc::rocket_helper::handle_prpc;
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    mtls::Certificate,
    post,
    response::{status::Custom, stream::TextStream},
    routes, Route, State,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

macro_rules! file_or_include_str {
    ($path:literal) => {
        fs::metadata($path)
            .is_ok()
            .then(|| fs::read_to_string($path).ok())
            .flatten()
            .unwrap_or_else(|| include_str!($path).to_string())
    };
}

#[post("/<method>?<json>", data = "<data>")]
#[allow(clippy::too_many_arguments)]
async fn prpc_post(
    state: &State<App>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Custom<Vec<u8>> {
    handle_prpc::<_, HostApiHandler>(
        state,
        cert,
        None,
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
}

#[get("/<method>")]
async fn prpc_get(
    state: &State<App>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Custom<Vec<u8>> {
    handle_prpc::<_, HostApiHandler>(state, None, None, method, None, limits, content_type, true).await
}

pub fn routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}
