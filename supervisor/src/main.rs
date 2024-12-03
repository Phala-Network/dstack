use anyhow::{anyhow, Context, Result};
use clap::Parser;
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

fn app_version() -> String {
    const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
    const VERSION: &str = git_version::git_version!(
        args = ["--abbrev=20", "--always", "--dirty=-modified"],
        prefix = "git:",
        fallback = "unknown"
    );
    format!("v{CARGO_PKG_VERSION} ({VERSION})")
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
    /// bind address
    #[arg(short, long)]
    address: Option<String>,
    /// bind port
    #[arg(short, long)]
    port: Option<u16>,
}

#[rocket::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut figment = load_config_figment(args.config.as_deref());
    if let Some(address) = args.address {
        figment = figment.join(("address", address));
    }
    if let Some(port) = args.port {
        figment = figment.join(("port", port));
    }
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
