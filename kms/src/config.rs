use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub tmp_ca_cert: String,
    pub tmp_ca_key: String,
    pub root_ca_cert: String,
    pub root_ca_key: String,
    pub rpc_cert: String,
    pub rpc_key: String,
    pub k256_key: String,
    pub subject_postfix: String,
    pub pccs_url: String,
    pub boot_authority: BootAuthority,
    pub onboard: OnboardConfig,
}

impl KmsConfig {
    pub fn keys_exists(&self) -> bool {
        std::fs::metadata(&self.tmp_ca_cert).is_ok()
            && std::fs::metadata(&self.tmp_ca_key).is_ok()
            && std::fs::metadata(&self.root_ca_cert).is_ok()
            && std::fs::metadata(&self.root_ca_key).is_ok()
            && std::fs::metadata(&self.rpc_cert).is_ok()
            && std::fs::metadata(&self.rpc_key).is_ok()
            && std::fs::metadata(&self.k256_key).is_ok()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum BootAuthority {
    #[serde(rename = "dev")]
    Dev,
    #[serde(rename = "webhook")]
    Webhook(Webhook),
}

impl BootAuthority {
    pub fn is_dev(&self) -> bool {
        matches!(self, BootAuthority::Dev)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Webhook {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OnboardConfig {
    pub enabled: bool,
    pub quote_enabled: bool,
}
