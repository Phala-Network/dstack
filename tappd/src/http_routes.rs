use crate::rpc_service::{list_containers, AppState, ExternalRpcHandler, InternalRpcHandler};
use anyhow::Result;
use ra_rpc::{rocket_helper::handle_prpc, RpcCall};
use rocket::futures::StreamExt;
use rocket::response::stream::TextStream;
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

    let containers = list_containers().await.unwrap_or_default().containers;
    let containers_str = containers
        .iter()
        .map(|c| serde_json::to_string_pretty(&c).unwrap_or_default())
        .collect::<Vec<String>>()
        .join("\n\n");

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
            <h2>App Certificate:</h2>
            <textarea readonly>{app_cert}</textarea>
            <h2>Deployed Containers:</h2>
            <textarea readonly>{containers_str}</textarea>
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

#[get("/logs/<container_name>?<since>&<until>&<follow>&<text>&<timestamps>")]
fn get_logs(
    container_name: String,
    since: Option<i64>,
    until: Option<i64>,
    follow: bool,
    text: bool,
    timestamps: bool,
) -> TextStream![String] {
    TextStream! {
        let mut stream = match docker_logs::get_logs(&container_name, since.unwrap_or(0), until.unwrap_or(0), follow, text, timestamps) {
            Ok(stream) => stream,
            Err(e) => {
                yield serde_json::json!({ "error": e.to_string() }).to_string();
                return;
            }
        };
        while let Some(log) = stream.next().await {
            match log {
                Ok(log) => yield log,
                Err(e) => yield serde_json::json!({ "error": e.to_string() }).to_string(),
            }
        }
    }
}

pub fn external_routes() -> Vec<Route> {
    routes![index, external_prpc_post, external_prpc_get, get_logs]
}

mod docker_logs {
    use anyhow::Result;
    use base64::Engine;
    use bollard::container::{LogOutput, LogsOptions};
    use bollard::Docker;
    use rocket::futures::{Stream, StreamExt};

    pub fn get_logs(
        container_name: &str,
        since: i64,
        until: i64,
        follow: bool,
        text: bool,
        timestamps: bool,
    ) -> Result<impl Stream<Item = Result<String, bollard::errors::Error>>> {
        let docker = Docker::connect_with_local_defaults()?;
        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            since,
            until,
            follow,
            timestamps,
            ..Default::default()
        };

        Ok(docker
            .logs(container_name, Some(options))
            .map(move |result| result.map(|m| log_to_json(m, text))))
    }

    fn log_to_json(log: LogOutput, text: bool) -> String {
        let channel = match &log {
            LogOutput::StdErr { .. } => "stderr",
            LogOutput::StdOut { .. } => "stdout",
            LogOutput::StdIn { .. } => "stdin",
            LogOutput::Console { .. } => "console",
        };

        let message: &[u8] = log.as_ref();
        let message = if text {
            String::from_utf8_lossy(message).to_string()
        } else {
            base64::engine::general_purpose::STANDARD.encode(message)
        };
        let log_json = serde_json::json!({
            "channel": channel,
            "message": message,
        })
        .to_string();
        format!("{log_json}\n")
    }
}
