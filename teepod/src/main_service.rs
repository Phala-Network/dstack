use anyhow::{Context, Result};
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{CreateVmRequest, VmInfo, VmListResponse, Id};

use crate::app::{App, Manifest};

fn hex_sha256(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct RpcHandler {
    state: App,
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: CreateVmRequest) -> Result<VmInfo> {
        let address = hex_sha256(&request.compose_file);
        let work_dir = self.state.vm_dir().join(&address);
        if work_dir.exists() {
            anyhow::bail!("VM already exists");
        }
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(
            shared_dir.join("docker-compose.yaml"),
            &request.compose_file,
        )
        .context("Failed to write compose file")?;

        let manifest = Manifest::builder()
            .name(address.clone())
            .image(request.image)
            .vcpu(request.vcpu)
            .memory(request.memory)
            .disk_size(request.disk_size)
            .port_map(Default::default())
            .build();

        let serialized_manifest =
            serde_json::to_string(&manifest).context("Failed to serialize manifest")?;
        fs::write(work_dir.join("config.json"), serialized_manifest)
            .context("Failed to write manifest")?;

        self.state.load_vm(work_dir)?;

        Ok(VmInfo {
            id: address,
            status: "created".to_string(),
        })
    }

    async fn stop_vm(self, request: Id) -> Result<VmInfo> {
        self.state.stop_vm(&request.id)?;
        Ok(VmInfo {
            id: request.id,
            status: Default::default(),
        })
    }

    async fn vm_status(self, request: Id) -> Result<VmInfo> {
        todo!()
    }

    async fn list_vms(self) -> Result<VmListResponse> {
        todo!()
    }
}

impl RpcCall<App> for RpcHandler {
    type PrpcService = TeepodServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TeepodServer::new(self)
    }

    fn construct(state: &App, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <TeepodServer<RpcHandler>>::supported_methods()
}
