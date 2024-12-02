use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::Config;
use rocket::fairing::AdHoc;
use rocket_apitoken::ApiToken;

mod app;
mod config;
mod main_service;
mod vm;
mod web_routes;

fn app_version() -> String {
    const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
    const VERSION: &str = git_version::git_version!(
        args = ["--abbrev=20", "--always", "--dirty=-modified"],
        prefix = "git:",
        fallback = "unknown"
    );
    format!("v{CARGO_PKG_VERSION} ({VERSION})")
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[rocket::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());
    let config = Config::extract_or_default(&figment)?;
    let api_auth = ApiToken::new(config.auth.tokens.clone(), config.auth.enabled);
    let state = app::App::new(config);
    state.reload_vms().context("Failed to reload VMs")?;
    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state)
        .manage(api_auth)
        .attach(AdHoc::on_response("Add app rev header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .attach(AdHoc::on_response("Disable buffering", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-Accel-Buffering", "no");
            })
        }));
    web_routes::print_endpoints();
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
