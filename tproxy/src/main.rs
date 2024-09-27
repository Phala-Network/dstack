use anyhow::{anyhow, Result};
use config::Config;
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
    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());
    let config = figment.extract::<Config>()?;
    let state = main_service::AppState::new(config);
    state.lock().reconfigure()?;
    let rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
