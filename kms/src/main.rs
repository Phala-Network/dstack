use anyhow::{anyhow, Context, Result};
use tracing::info;

mod config;
mod main_service;
mod web_routes;

#[rocket::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting KMS");
    info!("Supported methods:");
    for method in main_service::rpc_methods() {
        info!("  {method}");
    }

    let config = config::KmsConfig::load().context("Failed to read config file")?;
    let state = main_service::KmsState::new(config);

    let figment = config::load_config_figment().select("public");
    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);

    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
