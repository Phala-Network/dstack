use anyhow::{Context, Result};
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::Deserialize;

pub const CONFIG_FILENAME: &str = "teepod.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/teepod/teepod.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../teepod.toml");

pub fn load_config_figment() -> Figment {
    Figment::from(rocket::Config::default())
        .merge(Toml::string(DEFAULT_CONFIG).nested())
        .merge(Toml::file(SYSTEM_CONFIG_FILENAME).nested())
        .merge(Toml::file(CONFIG_FILENAME).nested())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub lib_path: String,
    #[serde(default)]
    pub run_path: String,
    #[serde(default)]
    pub qemu_path: String,
}

impl Config {
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".teepod");
            if me.lib_path.is_empty() {
                me.lib_path = app_home.join("image").to_string_lossy().to_string();
            }
            if me.run_path.is_empty() {
                me.run_path = app_home.join("run").to_string_lossy().to_string();
            }
            if me.qemu_path.is_empty() {
                let cpu_arch = std::env::consts::ARCH;
                let qemu_path = which::which(format!("qemu-system-{}", cpu_arch))
                    .context("Failed to find qemu-system-x86_64")?;
                me.qemu_path = qemu_path.to_string_lossy().to_string();
            }
        }
        Ok(me)
    }
}
