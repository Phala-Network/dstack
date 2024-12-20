use figment::Figment;
use load_config::load_config;
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = include_str!("../tappd.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("tappd", DEFAULT_CONFIG, config_file, true)
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub app_name: String,
    pub cert_file: String,
    pub key_file: String,
    pub public_logs: bool,
    pub public_sysinfo: bool,
}
