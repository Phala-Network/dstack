use crate::app::App;
use crate::main_service::{rpc_methods, RpcHandler};
use anyhow::Result;
use ra_rpc::rocket_helper::handle_prpc;
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    info,
    mtls::Certificate,
    post,
    response::status::Custom,
    routes, Route, State,
};

#[get("/")]
async fn index() -> (ContentType, String) {
    let html = include_str!("console.html");
    (ContentType::HTML, html.to_string())
}

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn prpc_post(
    state: &State<App>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, RpcHandler>(
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
    state: &State<App>,
    cert: Option<Certificate<'_>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, RpcHandler>(&*state, cert, method, None, limits, content_type, true)
        .await
        .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/logs?<id>")]
fn vm_logs(app: &State<App>, id: String) -> String {
    app.get_log(&id)
        .unwrap_or_else(|e| format!("Failed to get log: {e}"))
}

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get, vm_logs]
}

pub fn print_endpoints() {
    info!("  prpc endpoints:");
    for m in rpc_methods() {
        info!("    /prpc/{}", m);
    }
}
