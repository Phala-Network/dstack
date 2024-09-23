use anyhow::{anyhow, Result};
use config::Config;

mod app;
mod config;
mod main_service;
mod vm;
mod web_routes;

#[rocket::main]
async fn main() -> Result<()> {
    let figment = config::load_config_figment();
    let config = Config::extract_or_default(&figment)?;
    let state = app::App::new(config);
    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);
    web_routes::print_endpoints();
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
