use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Deserialize)]
pub struct WgConfig {
    pub public_key: String,
    pub private_key: String,
    pub listen_port: u16,
    pub ip: Ipv4Addr,
    pub client_ip_range: Ipv4Net,
    pub interface: String,
    pub config_path: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortMap {
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub target_port: u16,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub cert_chain: String,
    pub cert_key: String,
    pub base_domain: String,
    pub config_path: String,
    pub portmap: Vec<PortMap>,
    pub tls_passthrough: TlsPassthroughConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsPassthroughConfig {
    pub listen_addr: Ipv4Addr,
    pub listen_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertbotConfig {
    pub workdir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub wg: WgConfig,
    pub proxy: ProxyConfig,
    pub certbot: CertbotConfig,
}

impl Config {
    pub fn compute(&self) -> Result<ComputedConfig> {
        let tappd_port_map = self
            .proxy
            .portmap
            .iter()
            .find(|p| p.label.as_deref() == Some("tappd"))
            .context("tappd port map not found")?
            .clone();
        Ok(ComputedConfig { tappd_port_map })
    }
}

#[derive(Debug, Clone)]
pub struct ComputedConfig {
    pub tappd_port_map: PortMap,
}

pub const CONFIG_FILENAME: &str = "tproxy.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/tproxy/tproxy.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../tproxy.toml");

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
