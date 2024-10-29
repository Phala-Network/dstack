use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rocket::{
    figment::Figment,
    listener::{Bind, DefaultListener},
};
use rpc_service::AppState;

mod config;
mod http_routes;
mod rpc_service;
mod models;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

async fn run_internal(state: AppState, figment: Figment) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount("/", http_routes::internal_routes())
        .manage(state);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    let endpoint = DefaultListener::bind_endpoint(&ignite)
        .map_err(|err| anyhow!("Failed to get endpoint: {err}"))?;
    let listener = DefaultListener::bind(&ignite)
        .await
        .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?;
    if let Some(path) = endpoint.unix() {
        // Allow any user to connect to the socket
        fs_err::set_permissions(path, Permissions::from_mode(0o777))?;
    }
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

async fn run_external(state: AppState, figment: Figment) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount("/", http_routes::external_routes())
        .manage(state);
    let _ = rocket
        .launch()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());
    let state =
        AppState::new(figment.focus("core").extract()?).context("Failed to create app state")?;

    let internal_figment = figment.clone().select("internal");
    let external_figment = figment.clone().select("external");
    let external_https_figment = figment.select("external-https");
    tokio::select!(
        res = run_internal(state.clone(), internal_figment) => res?,
        res = run_external(state.clone(), external_figment) => res?,
        res = run_external(state, external_https_figment) => res?
    );
    Ok(())
}
