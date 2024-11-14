use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::Config;

mod app;
mod config;
mod main_service;
mod vm;
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
    let figment = config::load_config_figment(args.config.as_deref());
    let config = Config::extract_or_default(&figment)?;
    let state = app::App::new(config);
    state.reload_vms().context("Failed to reload VMs")?;
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
