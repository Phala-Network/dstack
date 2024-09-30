use anyhow::{anyhow, Result};
use clap::Parser;
use config::Config;

mod config;
mod main_service;
mod proxy;
mod web_routes;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[rocket::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let config = figment.focus("core").extract::<Config>()?;
    let proxy_config_path = config.proxy.config_path.clone();
    let state = main_service::AppState::new(config);
    state.lock().reconfigure()?;
    proxy::start_proxy(proxy_config_path, state.lock().subscribe_reconfigure());

    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
