use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    process::Command,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{bail, Context, Result};
use fs_err as fs;
use minijinja::context;
use ra_rpc::{Attestation, RpcCall};
use serde::{Deserialize, Serialize};
use tproxy_rpc::{
    tproxy_server::{TproxyRpc, TproxyServer},
    RegisterCvmRequest, RegisterCvmResponse,
};
use tracing::{error, info};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<AppStateInner>>,
}

pub(crate) struct AppStateInner {
    config: Config,
    // The mapping from the host name to the IP address.
    hosts: BTreeMap<String, HostInfo>,
    allocated_addresses: BTreeSet<Ipv4Addr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostInfo {
    id: String,
    ip: Ipv4Addr,
    public_key: String,
}

impl AppState {
    pub(crate) fn lock(&self) -> MutexGuard<AppStateInner> {
        self.inner.lock().expect("failed to lock AppState")
    }

    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AppStateInner {
                config,
                hosts: BTreeMap::new(),
                allocated_addresses: BTreeSet::new(),
            })),
        }
    }
}

impl AppStateInner {
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if ip == self.config.wg.ip {
                continue;
            }
            if self.allocated_addresses.contains(&ip) {
                continue;
            }
            self.allocated_addresses.insert(ip);
            return Some(ip);
        }
        None
    }

    fn new_client_by_id(&mut self, id: &str, public_key: &str) -> Option<HostInfo> {
        let ip = self.alloc_ip()?;
        if let Some(existing) = self.hosts.get(id) {
            if existing.public_key == public_key {
                return Some(existing.clone());
            }
        }
        let host_info = HostInfo {
            id: id.to_string(),
            ip,
            public_key: public_key.to_string(),
        };
        let todo = "support for multiple clients per app";
        self.hosts.insert(id.to_string(), host_info.clone());
        if let Err(err) = self.reconfigure() {
            error!("failed to reconfigure: {}", err);
        }
        Some(host_info)
    }

    fn generate_wg_config(&self) -> Result<String> {
        let peers = self.hosts.values().cloned().collect::<Vec<_>>();
        let template = include_str!("./templates/wg.conf");
        render_template(
            template,
            context! {
                peers => peers,
                private_key => self.config.wg.private_key,
                listen_port => self.config.wg.listen_port,
                ip => self.config.wg.ip,
            },
        )
    }

    fn generate_proxy_config(&self) -> Result<String> {
        let peers = self.hosts.values().cloned().collect::<Vec<_>>();
        let template = include_str!("./templates/rproxy.yaml");
        render_template(
            template,
            context! {
                listen_addr => self.config.proxy.listen_addr,
                listen_port => self.config.proxy.listen_port,
                cert_chain => self.config.proxy.cert_chain,
                cert_key => self.config.proxy.cert_key,
                base_domain => self.config.proxy.base_domain,
                target_port => self.config.proxy.target_port,
                peers => peers,
            },
        )
    }

    fn reconfigure(&mut self) -> Result<()> {
        let wg_config = self.generate_wg_config()?;
        fs::write(&self.config.wg.config_path, wg_config)?;
        // wg setconf <interface_name> <config_path>
        let output = Command::new("wg")
            .arg("setconf")
            .arg(&self.config.wg.interface)
            .arg(&self.config.wg.config_path)
            .output()?;
        if !output.status.success() {
            bail!("failed to set wg config: {}", output.status);
        }
        info!("wg config updated");

        let proxy_config = self.generate_proxy_config()?;
        fs::write(&self.config.proxy.config_path, proxy_config)?;
        let todo = "better way to notify rproxy to reload config";
        let output = Command::new("service")
            .arg("rproxy")
            .arg("restart")
            .output()?;
        if !output.status.success() {
            bail!("failed to restart rproxy: {}", output.status);
        }
        info!("rproxy config updated");
        Ok(())
    }
}

fn render_template(template: &str, data: impl Serialize) -> Result<String> {
    use minijinja::Environment;
    let mut env = Environment::new();
    env.add_template("tmpl", template)?;
    let template = env.get_template("tmpl")?;
    Ok(template.render(data)?)
}

pub struct RpcHandler {
    attestation: Option<Attestation>,
    state: AppState,
}

impl TproxyRpc for RpcHandler {
    async fn register_cvm(self, request: RegisterCvmRequest) -> Result<RegisterCvmResponse> {
        let Some(ra) = &self.attestation else {
            bail!("no attestation provided");
        };
        let app_id = ra
            .decode_app_id()
            .context("failed to decode app-id from attestation")?;
        let mut state = self.state.lock();
        let client_info = state
            .new_client_by_id(&app_id, &request.client_public_key)
            .context("failed to allocate IP address for client")?;

        Ok(RegisterCvmResponse {
            server_public_key: state.config.wg.public_key.clone(),
            client_ip: client_info.ip.to_string(),
            server_ip: state.config.wg.ip.to_string(),
            server_endpoint: state.config.wg.endpoint.clone(),
        })
    }
}

impl RpcCall<AppState> for RpcHandler {
    type PrpcService = TproxyServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TproxyServer::new(self)
    }

    fn construct(state: &AppState, attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            attestation,
            state: state.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
