use anyhow::{anyhow, Context, Result};
use rocket::{
    figment::{
        providers::{Format, Toml},
        Figment,
    },
    listener::{Bind, DefaultListener},
};
use supervisor::web_api;

pub const CONFIG_FILENAME: &str = "supervisor.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/supervisor/supervisor.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../supervisor.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    let leaf_config = match config_file {
        Some(path) => Toml::file(path).nested(),
        None => Toml::file(CONFIG_FILENAME).nested(),
    };
    Figment::from(rocket::Config::default())
        .merge(Toml::string(DEFAULT_CONFIG).nested())
        .merge(Toml::file(SYSTEM_CONFIG_FILENAME).nested())
        .merge(leaf_config)
}

#[rocket::main]
async fn main() -> Result<()> {
    let figment = load_config_figment(None);
    let rocket = web_api::rocket(figment);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to ignite rocket")?;
    let endpoint = DefaultListener::bind_endpoint(&ignite)
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to get endpoint")?;
    let listener = DefaultListener::bind(&ignite)
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context(format!("Failed to bind on {endpoint}"))?;
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to launch rocket")?;
    Ok(())
}
