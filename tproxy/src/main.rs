use anyhow::{anyhow, Result};
use clap::Parser;
use config::Config;
use ra_rpc::rocket_helper::QuoteVerifier;
use rocket::fairing::AdHoc;

mod config;
mod main_service;
mod models;
mod proxy;
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
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let config = figment.focus("core").extract::<Config>()?;
    let proxy_config = config.proxy.clone();
    let pccs_url = config.pccs_url.clone();
    let state = main_service::AppState::new(config)?;
    state.lock().reconfigure()?;
    proxy::start(proxy_config, state.clone());

    let mut rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .manage(state);
    if !pccs_url.is_empty() {
        let verifier = QuoteVerifier::new(pccs_url);
        rocket = rocket.manage(verifier);
    }
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
