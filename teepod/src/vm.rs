mod image {
    use std::{
        fs::File,
        path::{Path, PathBuf},
    };

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
    }

    impl ImageInfo {
        pub fn new(filename: PathBuf) -> Result<Self> {
            let file = File::open(filename).context("failed to open image info")?;
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
            let base_path = base_path.as_ref().canonicalize()?;
            let info = ImageInfo::new(base_path.join("info.json"))?;
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

pub(crate) mod run {
    pub use super::image::Image;
    pub use super::qemu::VmConfig;
    use anyhow::{bail, Result};
    use shared_child::SharedChild;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Instant;

    pub struct VmInstance {
        config: VmConfig,
        workdir: PathBuf,
        process: Option<Arc<SharedChild>>,
        exited_at: Option<Instant>,
        started_at: Option<Instant>,
    }

    impl VmInstance {
        pub fn new(config: VmConfig, workdir: PathBuf) -> Self {
            Self {
                config,
                workdir,
                process: None,
                exited_at: None,
                started_at: None,
            }
        }

        pub fn start(&mut self, qemu_bin: &str) -> Result<()> {
            let process = super::qemu::run_vm(qemu_bin, &self.config, &self.workdir)?;
            self.process = Some(process);
            self.started_at = Some(Instant::now());
            Ok(())
        }

        pub fn stop(&mut self) -> Result<()> {
            if let Some(process) = &self.process {
                process.kill()?;
                self.exited_at = Some(Instant::now());
            }
            Ok(())
        }
    }

    pub struct VmMonitor {
        qemu_bin: String,
        vms: BTreeMap<String, VmInstance>,
    }

    impl VmMonitor {
        pub fn new(qemu_bin: String) -> Self {
            Self {
                qemu_bin,
                vms: BTreeMap::new(),
            }
        }

        pub fn run_vm(&mut self, vm: VmConfig, workdir: impl AsRef<Path>) -> Result<()> {
            let mut vm = VmInstance::new(vm, workdir.as_ref().to_path_buf());
            vm.start(&self.qemu_bin)?;
            self.vms.insert(vm.config.id.clone(), vm);
            Ok(())
        }

        pub fn remove_vm(&mut self, id: &str) -> Result<Option<VmInstance>> {
            let Some(mut vm) = self.vms.remove(id) else {
                bail!("VM not found: {}", id);
            };
            vm.stop()?;
            Ok(Some(vm))
        }

        pub fn stop_vm(&mut self, id: &str) -> Result<()> {
            let Some(info) = self.vms.get_mut(id) else {
                bail!("VM not found: {}", id);
            };
            info.stop()?;
            Ok(())
        }
    }
}

mod qemu {
    //! QEMU related code
    use std::{collections::HashMap, path::Path, process::Command, sync::Arc};

    use super::image::Image;
    use anyhow::Result;
    use bon::Builder;
    use fs_err as fs;
    use shared_child::SharedChild;

    #[derive(Debug)]
    pub struct TdxConfig {
        /// Guest CID for vhost-vsock
        pub cid: u32,
    }

    #[derive(Debug, Builder)]
    pub struct VmConfig {
        pub id: String,
        pub process_name: String,
        pub vcpu: u32,
        /// Memory in MB
        pub memory: u32,
        pub disk_size: u32,
        pub image: Image,
        pub tdx_config: Option<TdxConfig>,
        /// Port map from host to guest
        pub port_map: HashMap<u16, u16>,
    }

    pub fn run_vm(
        qemu: &str,
        config: &VmConfig,
        workdir: impl AsRef<Path>,
    ) -> Result<Arc<SharedChild>> {
        let workdir = workdir.as_ref();
        let serial_file = workdir.join("serial.log");
        let shared_dir = workdir.join("shared");
        if !shared_dir.exists() {
            fs::create_dir_all(&shared_dir)?;
        }
        let mut command = Command::new(qemu);
        command.arg("-accel").arg("kvm");
        command.arg("-name").arg(&config.process_name);
        command.arg("-cpu").arg("host");
        command.arg("-smp").arg(config.vcpu.to_string());
        command.arg("-m").arg(format!("{}M", config.memory));
        command.arg("-nographic");
        command.arg("-nodefaults");
        command
            .arg("-serial")
            .arg(format!("file:{}", serial_file.display()));
        command.arg("-kernel").arg(&config.image.kernel);
        command.arg("-initrd").arg(&config.image.initrd);
        if let Some(hda) = &config.image.hda {
            command
                .arg("-drive")
                .arg(format!("file={},if=none,id=hd0", hda.display()))
                .arg("-device")
                .arg(format!("virtio-blk-pci,drive=hd0"));
        }
        if let Some(rootfs) = &config.image.rootfs {
            command.arg("-cdrom").arg(rootfs);
        }
        if let Some(bios) = &config.image.bios {
            command.arg("-bios").arg(bios);
        }
        let mut netdev = "user,id=net0,".to_string();
        for (host, guest) in &config.port_map {
            let todo = "rm portmap";
            netdev.push_str(&format!("hostfwd=tcp::{}-:{}", host, guest));
        }
        command.arg("-netdev").arg(netdev);
        command.arg("-device").arg("virtio-net-pci,netdev=net0");
        if let Some(tdx) = &config.tdx_config {
            command
                .arg("-machine")
                .arg("q35,kernel-irqchip=split,confidential-guest=tdx,hpet=off");
            command.arg("-object").arg("tdx-guest,id=tdx");
            command
                .arg("-device")
                .arg(format!("vhost-vsock-pci,guest-cid={}", tdx.cid));
        }
        command.arg("-virtfs").arg(format!(
            "local,path={},mount_tag=config,readonly=on,security_model=mapped,id=virtfs0",
            shared_dir.display()
        ));
        if let Some(cmdline) = &config.image.info.cmdline {
            command.arg("-append").arg(cmdline);
        }
        command.current_dir(workdir);
        let child = SharedChild::spawn(&mut command)?;
        Ok(Arc::new(child))
    }

    #[test]
    fn test_run_vm() {
        use literal::{map, MapLiteral};

        let image_path = paths::image_dir().join("ubuntu-24.04");
        let vm_dir = paths::vm_dir().join("test");

        let config = VmConfig {
            id: "test".to_string(),
            process_name: "test".to_string(),
            vcpu: 1,
            memory: 1024,
            image: Image::load(&image_path).unwrap(),
            tdx_config: None,
            port_map: map! {
                10022u16: 22u16,
            },
        };
        let child = run_vm("qemu-system-x86_64", &config, &vm_dir).unwrap();
        let status = child.wait().unwrap();
        println!("status: {:#?}", status);
    }
}
