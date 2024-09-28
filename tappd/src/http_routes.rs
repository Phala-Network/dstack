use crate::rpc_service::{AppState, ExternalRpcHandler, InternalRpcHandler};
use anyhow::Result;
use ra_rpc::{rocket_helper::handle_prpc, RpcCall};
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    mtls::Certificate,
    post,
    response::{content::RawHtml, status::Custom},
    routes, Route, State,
};
use tappd_rpc::{worker_server::WorkerRpc, WorkerInfo};

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
async fn index(state: &State<AppState>) -> Result<RawHtml<String>, String> {
    let handler = ExternalRpcHandler::construct(state, None)
        .map_err(|e| format!("Failed to construct RPC handler: {}", e))?;
    let WorkerInfo {
        app_id,
        tcb_info,
        app_cert,
    } = handler
        .info()
        .await
        .map_err(|e| format!("Failed to get worker info: {}", e))?;

    Ok(RawHtml(format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Worker Information</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    padding: 20px;
                    max-width: 800px;
                    margin: 0 auto;
                }}
                textarea {{
                    width: 100%;
                    height: 200px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <h1>Worker Information</h1>
            <p><strong>App ID:</strong> {app_id}</p>
            <h2>TCB Info:</h2>
            <textarea readonly>{tcb_info}</textarea>
            <h2>Certificate:</h2>
            <textarea readonly>{app_cert}</textarea>
        </body>
        </html>
        "#
    )))
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
