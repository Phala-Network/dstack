use crate::app::App;
use crate::main_service::{rpc_methods, RpcHandler};
use anyhow::Result;
use fs_err as fs;
use linemux::MuxedLines;
use ra_rpc::rocket_helper::handle_prpc;
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    info,
    mtls::Certificate,
    post,
    response::{status::Custom, stream::TextStream},
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

#[get("/logs?<id>&<follow>&<ansi>")]
fn vm_logs(app: &State<App>, id: String, follow: bool, ansi: bool) -> TextStream![String] {
    let log_file = app.get_log_file(&id);
    TextStream! {
        let log_file = match log_file {
            Err(err) => {
                yield format!("{err:?}");
                return;
            }
            Ok(log_file) => log_file,
        };
        if follow {
            let mut lines = match MuxedLines::new() {
                Err(err) => {
                    yield format!("{err:?}");
                    return;
                }
                Ok(lines) => lines,
            };
            if let Err(err) = lines.add_file(log_file).await {
                yield format!("{err:?}");
                return;
            }
            while let Ok(Some(line)) = lines.next_line().await {
                let line_str = line.line().to_string();
                if ansi {
                    yield line_str;
                } else {
                    yield strip_ansi_escapes::strip_str(&line_str);
                }
            }
        } else {
            let content = match fs::read_to_string(&log_file) {
                Err(err) => {
                    yield format!("{err:?}");
                    return;
                }
                Ok(content) => content,
            };
            if ansi {
                yield content;
            } else {
                yield strip_ansi_escapes::strip_str(&content);
            }
        }
    }
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
