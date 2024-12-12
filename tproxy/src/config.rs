use anyhow::{anyhow, bail, Result};
use ipnet::Ipv4Net;
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, process::Stdio};
use std::{process::Command, time::Duration};
use tracing::info;

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

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub cert_chain: String,
    pub cert_key: String,
    pub base_domain: String,
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub tappd_port: u16,
    pub timeouts: Timeouts,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Timeouts {
    #[serde(with = "serde_duration")]
    pub connect: Duration,
    #[serde(with = "serde_duration")]
    pub handshake: Duration,

    pub data_timeout_enabled: bool,
    #[serde(with = "serde_duration")]
    pub idle: Duration,
    #[serde(with = "serde_duration")]
    pub write: Duration,
    #[serde(with = "serde_duration")]
    pub shutdown: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertbotConfig {
    pub workdir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecycleConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
}

mod serde_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if duration == &Duration::MAX {
            return serializer.serialize_str("never");
        }
        let (value, unit) = if duration.as_secs() % (24 * 3600) == 0 {
            (duration.as_secs() / (24 * 3600), "d")
        } else if duration.as_secs() % 3600 == 0 {
            (duration.as_secs() / 3600, "h")
        } else if duration.as_secs() % 60 == 0 {
            (duration.as_secs() / 60, "m")
        } else {
            (duration.as_secs(), "s")
        };
        serializer.serialize_str(&format!("{}{}", value, unit))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom("Duration string cannot be empty"));
        }
        if s == "never" {
            return Ok(Duration::MAX);
        }
        let (value, unit) = s.split_at(s.len() - 1);
        let value = value.parse::<u64>().map_err(serde::de::Error::custom)?;

        let seconds = match unit {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 24 * 3600,
            _ => {
                return Err(serde::de::Error::custom(
                    "Invalid time unit. Use s, m, h, or d",
                ))
            }
        };

        Ok(Duration::from_secs(seconds))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub wg: WgConfig,
    pub proxy: ProxyConfig,
    pub certbot: CertbotConfig,
    pub pccs_url: String,
    pub recycle: RecycleConfig,
    pub state_path: String,
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

fn cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| anyhow!("Failed to run command {cmd}: {e}"))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to run command {cmd}: {error}");
    }
    Ok(output.stdout)
}

pub fn setup_wireguard(config: &WgConfig) -> Result<()> {
    info!("Setting up wireguard interface");

    let ifname = &config.interface;

    // Check if interface exists by trying to run ip link show
    let exists = cmd("ip", &["link", "show", &config.interface]).is_ok();
    if exists {
        info!("WireGuard interface {ifname} already exists");
        return Ok(());
    }

    let addr = format!("{}/{}", config.ip, config.client_ip_range.prefix_len());
    // Interface doesn't exist, create and configure it
    cmd("ip", &["link", "add", ifname, "type", "wireguard"])?;
    cmd("ip", &["address", "add", &addr, "dev", ifname])?;
    cmd("ip", &["link", "set", ifname, "up"])?;

    info!("Created and configured WireGuard interface {ifname}");

    Ok(())
}
