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
fn vm_logs(app: &State<App>, id: String) -> (ContentType, String) {
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Logs</title>
            <style>
                body {{ font-family: monospace; white-space: pre; background-color: #121212; color: #e0e0e0; }}
                #log-container {{ height: 90vh; overflow-y: scroll; border: 1px solid #333; padding: 10px; background-color: #1e1e1e; color: #e0e0e0; }}
            </style>
        </head>
        <body>
            <div id="log-container"></div>
            <script>
                async function fetchLogs() {{
                    const response = await fetch('/logs_plain?id={id}');
                    const logs = await response.text();
                    const logContainer = document.getElementById('log-container');
                    logContainer.textContent = logs;
                    logContainer.scrollTop = logContainer.scrollHeight;
                }}
                setInterval(fetchLogs, 1000);
                fetchLogs();
            </script>
        </body>
        </html>
        "#
    );
    (ContentType::HTML, html)
}

#[get("/logs_plain?<id>")]
fn vm_logs_plain(app: &State<App>, id: String) -> String {
    app.get_log(&id).unwrap_or_else(|e| format!("{e:?}"))
}

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get, vm_logs, vm_logs_plain]
}

pub fn print_endpoints() {
    info!("  prpc endpoints:");
    for m in rpc_methods() {
        info!("    /prpc/{}", m);
    }
}
