use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::Deserialize;

pub const CONFIG_FILENAME: &str = "tappd.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/tappd/tappd.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../tappd.toml");

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

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub cert_file: String,
    pub key_file: String,
}
