use anyhow::{Context, Result};
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};

pub const CONFIG_FILENAME: &str = "kms.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_file() -> Figment {
    Figment::from(Toml::string(DEFAULT_CONFIG).nested()).merge(Toml::file(CONFIG_FILENAME).nested())
}

#[derive(Debug, Clone)]
pub(crate) struct KmsConfig {
    pub allowed_mr: AllowedMr,
}

impl KmsConfig {
    pub fn load() -> Result<Self> {
        let figment = load_config_file();
        Self::from_figment(figment.select("core"))
    }
    pub fn from_figment(figment: Figment) -> Result<Self> {
        let allowed_mr = AllowedMr::from_figment(figment.focus("allowed_mr"))?;
        Ok(Self { allowed_mr })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AllowedMr {
    pub mrtd: Vec<[u8; 48]>,
    pub rtmr0: Vec<[u8; 48]>,
    pub rtmr1: Vec<[u8; 48]>,
    pub rtmr2: Vec<[u8; 48]>,
    pub rtmr3: Vec<[u8; 48]>,
}

impl AllowedMr {
    pub fn from_figment(figment: Figment) -> Result<Self> {
        fn read_mrlist(figment: &Figment, name: &str) -> Result<Vec<[u8; 48]>> {
            let list = figment
                .extract_inner::<Vec<String>>(name)
                .unwrap_or_default()
                .into_iter()
                .map(|s| {
                    let bytes = hex::decode(s)?;
                    let mr: [u8; 48] = bytes.try_into().ok().context("invalid MR config")?;
                    Ok(mr)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(list)
        }
        let mrtd = read_mrlist(&figment, "mrtd")?;
        let rtmr0 = read_mrlist(&figment, "rtmr0")?;
        let rtmr1 = read_mrlist(&figment, "rtmr1")?;
        let rtmr2 = read_mrlist(&figment, "rtmr2")?;
        let rtmr3 = read_mrlist(&figment, "rtmr3")?;

        Ok(Self {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        })
    }
}
