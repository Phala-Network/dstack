use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use tdx_attest as att;
use tracing::info;

use crate::{
    cmd_gen_app_keys, cmd_gen_ra_cert, cmd_show,
    utils::{copy_dir_all, deserialize_json_file, sha256_file, HashingFile},
    GenAppKeysArgs, GenRaCertArgs,
};
use serde_human_bytes as hex_bytes;

#[derive(clap::Parser)]
/// Prepare full disk encryption
pub struct SetupFdeArgs {
    /// Host shared directory
    #[arg(long)]
    host_shared: PathBuf,
    /// Copied host-shared directory
    #[arg(long)]
    host_shared_copy: PathBuf,
    /// Working directory
    #[arg(long)]
    work_dir: PathBuf,
    /// Root fs mount point
    #[arg(long)]
    rootfs_dir: PathBuf,
    /// Root hard disk device
    #[arg(long)]
    root_hd: String,
    /// Root fs cdrom device
    #[arg(long)]
    root_cdrom: String,
    /// Root fs cdrom mount point
    #[arg(long)]
    root_cdrom_mnt: PathBuf,
    /// Enabled rootfs integrity
    #[arg(long)]
    rootfs_integrity: bool,
}

fn extend_rtmr3(associated_data: &str, digest: &[u8]) -> Result<()> {
    if digest.len() > 48 {
        bail!("Digest too long");
    }
    let mut padded_digest: [u8; 48] = [0; 48];
    padded_digest[..digest.len()].copy_from_slice(&digest);
    let rtmr_event = att::TdxRtmrEvent {
        version: 1,
        rtmr_index: 3,
        digest: padded_digest,
        event_type: 1,
        event: associated_data.as_bytes().to_vec(),
    };
    att::extend_rtmr(&rtmr_event).context("Failed to extend RTMR")?;
    let hexed_digest = hex::encode(&padded_digest);
    println!("Extended RTMR3: {}", hexed_digest);
    att::log_rtmr_event(&rtmr_event).context("Failed to log RTMR extending event")?;
    Ok(())
}

fn run_command_with_stdin(command: &str, args: &[&str], stdin: &str) -> Result<()> {
    let mut child = Command::new("/usr/bin/env")
        .args(&[command])
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .context(format!("Failed to run {}", command))?;
    let mut child_stdin = child.stdin.take().context("Failed to get stdin")?;
    child_stdin
        .write_all(stdin.as_bytes())
        .context("Failed to write to stdin")?;
    drop(child_stdin);
    child
        .wait()
        .context(format!("Failed to wait for {}", command))?;
    Ok(())
}

fn run_command(command: &str, args: &[&str]) -> Result<()> {
    let output = Command::new("/usr/bin/env")
        .arg(command)
        .args(args)
        .status()
        .context(format!("Failed to run {}", command))?;
    if !output.success() {
        bail!("Command {} failed", command);
    }
    Ok(())
}

fn mount_9p(share_name: &str, mount_point: &str) -> Result<()> {
    run_command(
        "mount",
        &[
            "-t",
            "9p",
            "-o",
            "trans=virtio,version=9p2000.L",
            share_name,
            mount_point,
        ],
    )
}

fn mount_cdrom(cdrom_device: &str, mount_point: &str) -> Result<()> {
    run_command(
        "mount",
        &["-t", "iso9660", "-o", "ro", cdrom_device, mount_point],
    )
}

#[derive(Deserialize)]
struct VmConfig {
    #[serde(with = "hex_bytes")]
    rootfs_hash: Vec<u8>,
    kms_url: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct InstanceInfo {
    #[serde(with = "hex_bytes")]
    instance_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    app_id: Vec<u8>,
}

#[derive(Deserialize)]
struct AppKeys {
    disk_crypt_key: String,
}

struct HostShareDir {
    base_dir: PathBuf,
}

impl HostShareDir {
    fn new(host_shared_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: host_shared_dir.as_ref().to_path_buf(),
        }
    }

    fn app_compose_file(&self) -> PathBuf {
        self.base_dir.join("app-compose.json")
    }

    fn vm_config_file(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    fn instance_info_file(&self) -> PathBuf {
        self.base_dir.join(".instance_info")
    }

    fn kms_ca_cert_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("ca.cert")
    }

    fn tmp_ca_cert_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("tmp-ca.cert")
    }

    fn tmp_ca_key_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("tmp-ca.key")
    }
}

struct HostShared {
    vm_config: VmConfig,
    app_compose: AppCompose,
    instance_info: Option<InstanceInfo>,
}

impl HostShared {
    fn load(host_shared_dir: &HostShareDir) -> Result<Self> {
        let vm_config = deserialize_json_file(host_shared_dir.vm_config_file())?;
        let app_compose = deserialize_json_file(host_shared_dir.app_compose_file())?;
        let instance_info_file = host_shared_dir.instance_info_file();
        let instance_info = if instance_info_file.exists() {
            Some(deserialize_json_file(instance_info_file)?)
        } else {
            None
        };
        Ok(Self {
            vm_config,
            app_compose,
            instance_info,
        })
    }
}

#[derive(Deserialize)]
pub struct AppCompose {
    features: Vec<String>,
}

impl AppCompose {
    pub fn feature_enabled(&self, feature: &str) -> bool {
        self.features.contains(&feature.to_string())
    }
}

pub fn cmd_setup_fde(args: SetupFdeArgs) -> Result<()> {
    fs::create_dir_all(&args.host_shared).context("Failed to create host-sharing mount point")?;
    mount_9p("host-shared", &args.host_shared.display().to_string())
        .context("Failed to mount host-sharing")?;
    fs::create_dir_all(&args.host_shared_copy).context("Failed to create host-shared copy dir")?;
    copy_dir_all(&args.host_shared, &args.host_shared_copy)
        .context("Failed to copy host-shared dir")?;

    let host_shared_dir = HostShareDir::new(&args.host_shared_copy);
    let host_shared = HostShared::load(&host_shared_dir)?;

    let rootfs_hash = &host_shared.vm_config.rootfs_hash;
    let kms_url = &host_shared.vm_config.kms_url;
    let upgraded_app_id = sha256_file(host_shared_dir.app_compose_file())?;
    let kms_enabled = host_shared.app_compose.feature_enabled("kms");
    let ca_cert_hash = if kms_enabled {
        sha256_file(host_shared_dir.kms_ca_cert_file())?
    } else {
        sha256_file(host_shared_dir.tmp_ca_cert_file())?
    };
    let tapp_dir = args.rootfs_dir.join("tapp");
    let app_keys_file = args.work_dir.join("appkeys.json");

    let app_id;
    let instance_id;
    let bootstraped;

    match host_shared.instance_info {
        Some(instance_info) if kms_enabled => {
            app_id = instance_info.app_id.clone();
            instance_id = instance_info.instance_id.clone();
            bootstraped = true;
        }
        _ => {
            app_id = upgraded_app_id.to_vec();
            let mut rand_id = vec![0u8; 20];
            getrandom::getrandom(&mut rand_id)?;
            instance_id = rand_id;
            bootstraped = false;
        }
    }

    extend_rtmr3("rootfs-hash", rootfs_hash)?;
    extend_rtmr3("app-id", &app_id)?;
    extend_rtmr3("upgraded-app-id", &upgraded_app_id)?;
    extend_rtmr3("ca-cert-hash", &ca_cert_hash)?;
    extend_rtmr3("instance-id", &instance_id)?;

    // Show the RTMR
    cmd_show()?;

    if kms_enabled {
        let Some(kms_url) = kms_url else {
            bail!("KMS URL is not set");
        };
        info!("KMS is enabled, generating RA-TLS cert");
        let gen_certs_dir = args.work_dir.join("certs");
        fs::create_dir_all(&gen_certs_dir).context("Failed to create certs dir")?;
        cmd_gen_ra_cert(GenRaCertArgs {
            ca_cert: host_shared_dir.tmp_ca_cert_file(),
            ca_key: host_shared_dir.tmp_ca_key_file(),
            cert_path: gen_certs_dir.join("cert.pem"),
            key_path: gen_certs_dir.join("key.pem"),
        })?;
        info!("Requesting app keys from KMS: {kms_url}");
        let todo = "use rust library";
        run_command(
            "curl",
            &[
                "--cacert",
                &host_shared_dir.kms_ca_cert_file().display().to_string(),
                "--cert",
                &gen_certs_dir.join("cert.pem").display().to_string(),
                "--key",
                &gen_certs_dir.join("key.pem").display().to_string(),
                "-o",
                &app_keys_file.display().to_string(),
                &format!("{kms_url}/prpc/KMS.GetAppKey"),
            ],
        )?;
    } else {
        info!("KMS is not enabled, generating local app keys");
        cmd_gen_app_keys(GenAppKeysArgs {
            ca_cert: host_shared_dir.tmp_ca_cert_file(),
            ca_key: host_shared_dir.tmp_ca_key_file(),
            ca_level: 1,
            output: app_keys_file.clone(),
        })?;
    }
    let app_keys: AppKeys =
        deserialize_json_file(&app_keys_file).context("Failed to decode app keys")?;
    if app_keys.disk_crypt_key.is_empty() {
        bail!("Failed to get valid key phrase from KMS");
    }
    let disk_crypt_key = format!("{}\n", app_keys.disk_crypt_key);
    if bootstraped {
        info!("Mounting rootfs");
        run_command_with_stdin(
            "cryptsetup",
            &[
                "luksOpen",
                "--type",
                "luks2",
                "-d-",
                &args.root_hd,
                "rootfs_crypt",
            ],
            &disk_crypt_key,
        )
        .context("Failed to open encrypted rootfs")?;
        run_command(
            "mount",
            &[
                "/dev/mapper/rootfs_crypt",
                &args.rootfs_dir.display().to_string(),
            ],
        )
        .context("Failed to mount rootfs")?;
    } else {
        info!("Setting up disk encryption");
        fs::create_dir_all(&args.root_cdrom_mnt)
            .context("Failed to create rootfs cdrom mount point")?;
        mount_cdrom(&args.root_cdrom, &args.root_cdrom_mnt.display().to_string())
            .context("Failed to mount rootfs cdrom")?;
        info!("Formatting rootfs");
        let mut cmd_args = vec![
            "luksFormat",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--pbkdf",
            "pbkdf2",
            "-d-",
        ];
        if args.rootfs_integrity {
            cmd_args.push("--integrity");
            cmd_args.push("hmac-sha256");
        }
        cmd_args.push(&args.root_hd);

        run_command_with_stdin("cryptsetup", &cmd_args, &disk_crypt_key)
            .context("Failed to format encrypted rootfs")?;
        info!("Formatting rootfs done, opening the device");
        run_command_with_stdin(
            "cryptsetup",
            &[
                "luksOpen",
                "--type",
                "luks2",
                "-d-",
                &args.root_hd,
                "rootfs_crypt",
            ],
            &disk_crypt_key,
        )
        .context("Failed to open encrypted rootfs")?;
        run_command(
            "mkfs.ext4",
            &["-L", "cloudimg-rootfs", "/dev/mapper/rootfs_crypt"],
        )
        .context("Failed to create ext4 filesystem")?;
        run_command(
            "mount",
            &[
                "/dev/mapper/rootfs_crypt",
                &args.rootfs_dir.display().to_string(),
            ],
        )
        .context("Failed to mount rootfs")?;

        info!("Extracting rootfs");

        let rootfs_cpio = args.root_cdrom_mnt.join("rootfs.cpio");
        if !rootfs_cpio.exists() {
            bail!("Rootfs cpio file not found on cdrom");
        }
        let rootfs_cpio_file =
            fs::File::open(rootfs_cpio).context("Failed to open rootfs cpio file")?;
        let mut hashing_rootfs_cpio = HashingFile::<sha2::Sha256, _>::new(rootfs_cpio_file);
        let mut status = Command::new("/usr/bin/env")
            .args(&["cpio", "-i"])
            .current_dir(&args.rootfs_dir)
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to extract rootfs")?;

        {
            let mut stdin = status.stdin.take().context("Failed to get stdin")?;
            let mut buf = [0u8; 1024];
            loop {
                let n = hashing_rootfs_cpio.read(&mut buf).context("Failed to read from rootfs cpio")?;
                if n == 0 {
                    break;
                }
                stdin
                    .write_all(&buf[..n])
                    .context("Failed to write to stdin")?;
            }
            drop(stdin);
        }
        let status = status.wait().context("Failed to wait for cpio")?;
        if !status.success() {
            bail!("Failed to extract rootfs, cpio returned {status:?}");
        }
        let rootfs_hash = hashing_rootfs_cpio.finalize();
        if &rootfs_hash[..] != &host_shared.vm_config.rootfs_hash[..] {
            bail!("Rootfs hash mismatch");
        }
        info!("Rootfs hash is valid");
        copy_dir_all(&args.host_shared_copy, &tapp_dir).context("Failed to copy rootfs")?;
        // write instance info
        let instance_info = serde_json::to_string(&InstanceInfo {
            app_id,
            instance_id,
        })
        .context("Failed to serialize instance info")?;
        let origin_host_shared_dir = HostShareDir::new(&args.host_shared);
        fs::write(origin_host_shared_dir.instance_info_file(), instance_info)
            .context("Failed to write instance info")?;
        fs::File::create(args.rootfs_dir.join(".bootstraped"))
            .context("Failed to touch bootstraped")?;
        info!("Rootfs is ready");
    }
    fs::copy(&app_keys_file, &tapp_dir.join("appkeys.json"))
        .context("Failed to copy appkeys.json")?;
    fs::copy(
        &args.host_shared_copy.join("config.json"),
        &tapp_dir.join("config.json"),
    )
    .context("Failed to copy config.json")?;

    Ok(())
}
