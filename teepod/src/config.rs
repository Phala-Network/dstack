use std::path::PathBuf;

use anyhow::{Context, Result};
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::Deserialize;

pub const CONFIG_FILENAME: &str = "teepod.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/teepod/teepod.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../teepod.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    let leaf_config = match config_file {
        Some(path) => Toml::file(path),
        None => Toml::file(CONFIG_FILENAME),
    };
    Figment::from(rocket::Config::default())
        .merge(Toml::string(DEFAULT_CONFIG))
        .merge(Toml::file(SYSTEM_CONFIG_FILENAME))
        .merge(leaf_config)
}

#[derive(Debug, Clone, Deserialize)]
pub struct CvmConfig {
    pub ca_cert: PathBuf,
    pub tmp_ca_cert: PathBuf,
    pub tmp_ca_key: PathBuf,
    /// The URL of the KMS server
    pub kms_url: String,
    /// The URL of the TProxy server
    pub tproxy_url: String,
    /// The maximum disk size in GB
    pub max_disk_size: u32,
    /// The start of the CID pool that allocates CIDs to VMs
    pub cid_start: u32,
    /// The size of the CID pool that allocates CIDs to VMs
    pub cid_pool_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub base_domain: String,
    pub port: u16,
    pub tappd_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub image_path: PathBuf,
    #[serde(default)]
    pub run_path: PathBuf,
    #[serde(default)]
    pub qemu_path: PathBuf,

    /// CVM configuration
    pub cvm: CvmConfig,
    /// Gateway configuration
    pub gateway: GatewayConfig,
}

impl Config {
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".teepod");
            if me.image_path == PathBuf::default() {
                me.image_path = app_home.join("image");
            }
            if me.run_path == PathBuf::default() {
                me.run_path = app_home.join("vm");
            }
            if me.qemu_path == PathBuf::default() {
                let cpu_arch = std::env::consts::ARCH;
                let qemu_path = which::which(format!("qemu-system-{}", cpu_arch))
                    .context("Failed to find qemu-system-x86_64")?;
                me.qemu_path = qemu_path;
            }
        }
        Ok(me)
    }
}
