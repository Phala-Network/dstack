use anyhow::{anyhow, Context, Result};
use tracing::info;
use clap::Parser;

mod config;
mod main_service;
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
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Starting KMS");
    info!("Supported methods:");
    for method in main_service::rpc_methods() {
        info!("  /prpc/{method}");
    }

    let figment = config::load_config_figment(args.config.as_deref());
    let config = figment.clone().select("core").extract()?;
    let state = main_service::KmsState::new(config).context("Failed to initialize KMS state")?;
    let rocket = rocket::custom(figment.select("public"))
        .mount("/", web_routes::routes())
        .manage(state);

    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
