use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    // Deprecated
    #[serde(default)]
    pub features: Vec<String>,
    pub runner: String,
    pub docker_compose_file: Option<String>,
    #[serde(default)]
    pub docker_config: DockerConfig,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(default)]
    pub tproxy_enabled: bool,
    #[serde(default)]
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    pub key_provider: Option<KeyProvider>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum KeyProvider {
    None,
    Kms,
    Local,
}

impl KeyProvider {
    pub fn is_none(&self) -> bool {
        matches!(self, KeyProvider::None)
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct DockerConfig {
    /// The URL of the Docker registry.
    pub registry: Option<String>,
    /// The username of the registry account.
    pub username: Option<String>,
    /// The key of the encrypted environment variables for registry account token.
    pub token_key: Option<String>,
}

impl AppCompose {
    pub fn feature_enabled(&self, feature: &str) -> bool {
        self.features.contains(&feature.to_string())
    }

    pub fn tproxy_enabled(&self) -> bool {
        self.tproxy_enabled || self.feature_enabled("tproxy-net")
    }

    pub fn kms_enabled(&self) -> bool {
        self.kms_enabled || self.feature_enabled("kms")
    }

    pub fn key_provider(&self) -> KeyProvider {
        match self.key_provider {
            Some(p) => p,
            None => {
                if self.kms_enabled {
                    KeyProvider::Kms
                } else if self.local_key_provider_enabled {
                    KeyProvider::Local
                } else {
                    KeyProvider::None
                }
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LocalConfig {
    pub kms_url: Option<String>,
    pub tproxy_url: Option<String>,
    pub pccs_url: Option<String>,
    pub docker_registry: Option<String>,
    pub host_api_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppKeys {
    pub app_key: String,
    pub disk_crypt_key: String,
    #[serde(with = "hex_bytes", default)]
    pub env_crypt_key: Vec<u8>,
    pub certificate_chain: Vec<String>,
    #[serde(with = "hex_bytes")]
    pub k256_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub k256_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyProviderInfo {
    pub name: String,
    pub id: String,
}

impl KeyProviderInfo {
    pub fn new(name: String, id: String) -> Self {
        Self { name, id }
    }
}
