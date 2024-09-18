use anyhow::{anyhow, Context, Result};
use rocket::figment::Figment;
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

    let figment = Figment::from(rocket::Config::default())
        .merge(config::load_config_file())
        .select("public");
    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);

    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
