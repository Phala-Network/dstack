use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::{anyhow, Result};
use rpc_service::AppState;
use rocket::{
    figment::Figment,
    listener::{Bind, DefaultListener},
};

mod config;
mod http_routes;
mod rpc_service;

async fn run_http(state: AppState) -> Result<()> {
    let figment = Figment::from(rocket::Config::default()).merge(config::load_config_file());
    let rocket = rocket::custom(figment)
        .mount("/", http_routes::routes())
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
        std::fs::set_permissions(path, Permissions::from_mode(0o777))?;
    }
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    let state = AppState::new();
    run_http(state).await?;
    Ok(())
}
