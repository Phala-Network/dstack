pub(crate) mod image {
    use fs_err as fs;
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ImageInfo {
        pub cmdline: Option<String>,
        pub kernel: String,
        pub initrd: String,
        pub hda: Option<String>,
        pub rootfs: Option<String>,
        pub bios: Option<String>,
        pub rootfs_hash: Option<String>,
    }

    impl ImageInfo {
        pub fn load(filename: PathBuf) -> Result<Self> {
            let file = fs::File::open(filename).context("failed to open image info")?;
            let info: ImageInfo =
                serde_json::from_reader(file).context("failed to parse image info")?;
            Ok(info)
        }
    }

    #[derive(Debug)]
    pub struct Image {
        pub info: ImageInfo,
        pub initrd: PathBuf,
        pub kernel: PathBuf,
        pub hda: Option<PathBuf>,
        pub rootfs: Option<PathBuf>,
        pub bios: Option<PathBuf>,
    }

    impl Image {
        pub fn load(base_path: impl AsRef<Path>) -> Result<Self> {
            let base_path = fs::canonicalize(base_path.as_ref())?;
            let info = ImageInfo::load(base_path.join("metadata.json"))?;
            let initrd = base_path.join(&info.initrd);
            let kernel = base_path.join(&info.kernel);
            let hda = info.hda.as_ref().map(|hda| base_path.join(hda));
            let rootfs = info.rootfs.as_ref().map(|rootfs| base_path.join(rootfs));
            let bios = info.bios.as_ref().map(|bios| base_path.join(bios));
            Self {
                info,
                hda,
                initrd,
                kernel,
                rootfs,
                bios,
            }
            .ensure_exists()
        }

        fn ensure_exists(self) -> Result<Self> {
            if !self.initrd.exists() {
                bail!("Initrd does not exist: {}", self.initrd.display());
            }
            if !self.kernel.exists() {
                bail!("Kernel does not exist: {}", self.kernel.display());
            }
            if let Some(hda) = &self.hda {
                if !hda.exists() {
                    bail!("Hda does not exist: {}", hda.display());
                }
            }
            if let Some(rootfs) = &self.rootfs {
                if !rootfs.exists() {
                    bail!("Rootfs does not exist: {}", rootfs.display());
                }
            }
            if let Some(bios) = &self.bios {
                if !bios.exists() {
                    bail!("Bios does not exist: {}", bios.display());
                }
            }
            Ok(self)
        }
    }
}

mod qemu {
    //! QEMU related code
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        process::Command,
        sync::Arc,
    };

    use crate::{
        app::{Manifest, VmWorkDir},
        config::Networking,
    };

    use super::image::Image;
    use anyhow::Result;
    use bon::Builder;
    use fs_err as fs;
    use supervisor_client::supervisor::{ProcessConfig, ProcessInfo};

    #[derive(Debug, Deserialize)]
    pub struct InstanceInfo {
        pub instance_id: String,
    }

    pub struct VmInfo {
        pub manifest: Manifest,
        pub workdir: PathBuf,
        pub status: &'static str,
        pub uptime: String,
        pub exited_at: Option<String>,
        pub instance_id: Option<String>,
    }

    #[derive(Debug)]
    pub struct TdxConfig {
        /// Guest CID for vhost-vsock
        pub cid: u32,
    }

    #[derive(Debug, Builder)]
    pub struct VmConfig {
        pub manifest: Manifest,
        pub image: Image,
        pub tdx_config: Option<TdxConfig>,
        pub networking: Networking,
    }

    fn create_hd(
        image_file: impl AsRef<Path>,
        backing_file: Option<impl AsRef<Path>>,
        size: &str,
    ) -> Result<()> {
        let mut command = Command::new("qemu-img");
        command.arg("create").arg("-f").arg("qcow2");
        if let Some(backing_file) = backing_file {
            command
                .arg("-o")
                .arg(format!("backing_file={}", backing_file.as_ref().display()));
            command.arg("-o").arg("backing_fmt=qcow2");
        }
        command.arg(image_file.as_ref());
        command.arg(size);
        command.spawn()?.wait()?;
        Ok(())
    }

    impl VmConfig {
        pub fn merge_info(
            &self,
            states: &HashMap<String, ProcessInfo>,
            instance_id: Option<String>,
        ) -> VmInfo {
            fn truncate(d: Duration) -> Duration {
                Duration::from_secs(d.as_secs())
            }
            let info = states.get(&self.config.manifest.id);
            let is_running = match &info {
                Some(info) => info.state.status.is_running(),
                None => false,
            };
            let status = match (self.started, is_running) {
                (true, true) => "running",
                (true, false) => "exited",
                (false, true) => "stopping",
                (false, false) => "stopped",
            };

            fn display_ts(t: Option<&SystemTime>) -> String {
                match t {
                    None => "never".into(),
                    Some(t) => {
                        let ts = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::MAX);
                        humantime::format_duration(truncate(ts)).to_string()
                    }
                }
            }
            let uptime = display_ts(info.and_then(|info| info.state.started_at.as_ref()));
            let exited_at = display_ts(info.and_then(|info| info.state.stopped_at.as_ref()));

            VmInfo {
                manifest: self.config.manifest.clone(),
                workdir: self.workdir.clone(),
                instance_id,
                status,
                uptime,
                exited_at: Some(exited_at),
            }
        }

        pub fn config_qemu(&self, qemu: &Path, workdir: impl AsRef<Path>) -> Result<ProcessConfig> {
            let workdir = VmWorkDir::new(workdir);
            let serial_file = workdir.serial_file();
            let shared_dir = workdir.shared_dir();
            let disk_size = format!("{}G", self.manifest.disk_size);
            let hda_path = workdir.hda_path();
            if !hda_path.exists() {
                create_hd(&hda_path, self.image.hda.as_ref(), &disk_size)?;
            }
            if !shared_dir.exists() {
                fs::create_dir_all(&shared_dir)?;
            }
            let mut command = Command::new(qemu);
            command.arg("-accel").arg("kvm");
            command.arg("-cpu").arg("host");
            command.arg("-smp").arg(self.manifest.vcpu.to_string());
            command.arg("-m").arg(format!("{}M", self.manifest.memory));
            command.arg("-nographic");
            command.arg("-nodefaults");
            command
                .arg("-serial")
                .arg(format!("file:{}", serial_file.display()));
            command.arg("-kernel").arg(&self.image.kernel);
            command.arg("-initrd").arg(&self.image.initrd);
            command
                .arg("-drive")
                .arg(format!("file={},if=none,id=hd0", hda_path.display()))
                .arg("-device")
                .arg(format!("virtio-blk-pci,drive=hd0"));
            if let Some(rootfs) = &self.image.rootfs {
                command.arg("-cdrom").arg(rootfs);
            }
            if let Some(bios) = &self.image.bios {
                command.arg("-bios").arg(bios);
            }
            let netdev = match &self.networking {
                Networking::User(netcfg) => {
                    let mut netdev = format!(
                        "user,id=net0,net={},dhcpstart={},restrict={}",
                        netcfg.net,
                        netcfg.dhcp_start,
                        if netcfg.restrict { "yes" } else { "no" }
                    );
                    for pm in &self.manifest.port_map {
                        netdev.push_str(&format!(
                            ",hostfwd={}:{}:{}-:{}",
                            pm.protocol.as_str(),
                            pm.address,
                            pm.from,
                            pm.to
                        ));
                    }
                    netdev
                }
                Networking::Custom(netcfg) => netcfg.netdev.clone(),
            };
            command.arg("-netdev").arg(netdev);
            command.arg("-device").arg("virtio-net-pci,netdev=net0");
            if let Some(tdx) = &self.tdx_config {
                command
                    .arg("-machine")
                    .arg("q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off");
                command.arg("-object").arg("tdx-guest,id=tdx");
                command
                    .arg("-device")
                    .arg(format!("vhost-vsock-pci,guest-cid={}", tdx.cid));
            }
            command.arg("-virtfs").arg(format!(
                "local,path={},mount_tag=host-shared,readonly=off,security_model=mapped,id=virtfs0",
                shared_dir.display()
            ));
            if let Some(cmdline) = &self.image.info.cmdline {
                command.arg("-append").arg(cmdline);
            }

            let args = command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<_>>();

            let pidfile_path = workdir.pid_file();
            let stdout_path = workdir.stdout_file();
            let stderr_path = workdir.stderr_file();

            let workdir = workdir.path();
            let process_config = ProcessConfig {
                id: self.manifest.id.clone(),
                args,
                name: self.manifest.name.clone(),
                command: qemu.to_string_lossy().to_string(),
                env: Default::default(),
                cwd: workdir.to_string_lossy().to_string(),
                stdout: stdout_path.to_string_lossy().to_string(),
                stderr: stderr_path.to_string_lossy().to_string(),
                pidfile: pidfile_path.to_string_lossy().to_string(),
            };
            Ok(process_config)
        }
    }
}
