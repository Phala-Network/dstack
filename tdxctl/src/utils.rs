use std::{
    io::{self, Read},
    path::Path,
};

use anyhow::{Context, Result};
use fs_err as fs;
use serde::de::DeserializeOwned;
use sha2::{digest::Output, Digest};

pub fn deserialize_json_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let data = fs::read_to_string(path).context("Failed to read file")?;
    serde_json::from_str(&data).context("Failed to parse json")
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    sha256.finalize().into()
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let data = fs::read(path).context("Failed to read file")?;
    Ok(sha256(&data))
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src.as_ref())? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub struct HashingFile<H, F> {
    file: F,
    hasher: H,
}

impl<H: Digest, F: Read> Read for HashingFile<H, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.file.read(buf)?;
        self.hasher.update(&buf[..bytes_read]);
        Ok(bytes_read)
    }
}

impl<H: Digest, F> HashingFile<H, F> {
    pub fn new(file: F) -> Self {
        Self {
            file,
            hasher: H::new(),
        }
    }

    pub fn finalize(self) -> Output<H> {
        self.hasher.finalize()
    }
}
