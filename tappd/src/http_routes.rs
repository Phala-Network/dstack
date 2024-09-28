use crate::rpc_service::{AppState, ExternalRpcHandler, InternalRpcHandler};
use anyhow::Result;
use ra_rpc::rocket_helper::handle_prpc;
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    mtls::Certificate,
    post,
    response::status::Custom,
    routes, Route, State,
};

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn prpc_post(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, InternalRpcHandler>(
        &*state,
        cert,
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/prpc/<method>")]
async fn prpc_get(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, InternalRpcHandler>(&*state, cert, method, None, limits, content_type, true)
        .await
        .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

pub fn internal_routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}

#[get("/")]
async fn index() -> String {
    "Tappd Server is running!\n".to_string()
}

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn external_prpc_post(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, ExternalRpcHandler>(
        &*state,
        cert,
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/prpc/<method>")]
async fn external_prpc_get(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, ExternalRpcHandler>(&*state, cert, method, None, limits, content_type, true)
        .await
        .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

pub fn external_routes() -> Vec<Route> {
    routes![index, external_prpc_post, external_prpc_get]
}
