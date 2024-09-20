use std::path::PathBuf;

pub(crate) fn config_home() -> PathBuf {
    dirs::home_dir().unwrap().join(".teepod")
}

pub(crate) fn vm_dir() -> PathBuf {
    config_home().join("vm")
}

pub(crate) fn image_dir() -> PathBuf {
    config_home().join("image")
}
