use std::process::Command;

use anyhow::Result;
use fs_err as fs;
use guest_api::{
    guest_api_server::{GuestApiRpc, GuestApiServer},
    Gateway, GuestInfo, Interface, IpAddress, NetworkInformation,
};
use host_api::Notification;
use ra_rpc::{CallContext, RpcCall};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
struct LocalConfig {
    host_api_url: String,
}

pub struct GuestApiHandler;

impl RpcCall<AppState> for GuestApiHandler {
    type PrpcService = GuestApiServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        GuestApiServer::new(self)
    }

    fn construct(_context: CallContext<'_, AppState>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }
}

impl GuestApiRpc for GuestApiHandler {
    async fn info(self) -> Result<GuestInfo> {
        let guest_info = GuestInfo {
            name: "Tappd".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        Ok(guest_info)
    }

    async fn shutdown(self) -> Result<()> {
        tokio::spawn(async move {
            notify_q("shutdown.stopapp", "").await.ok();
            run_command("systemctl stop app-compose").ok();
            notify_q("shutdown", "").await.ok();
            run_command("systemctl poweroff").ok();
        });
        Ok(())
    }

    async fn network_info(self) -> Result<NetworkInformation> {
        let networks = sysinfo::Networks::new_with_refreshed_list();
        for (interface_name, network) in &networks {
            println!("[{interface_name}]: {network:?}");
        }
        Ok(NetworkInformation {
            dns_servers: get_dns_servers(),
            gateways: get_gateways(),
            interfaces: get_interfaces(),
        })
    }
}

fn get_interfaces() -> Vec<Interface> {
    sysinfo::Networks::new_with_refreshed_list()
        .into_iter()
        .map(|(interface_name, network)| Interface {
            name: interface_name.clone(),
            addresses: network
                .ip_networks()
                .into_iter()
                .map(|ip| IpAddress {
                    address: ip.addr.to_string(),
                    prefix: ip.prefix as u32,
                })
                .collect(),
            rx_bytes: network.total_received(),
            tx_bytes: network.total_transmitted(),
            rx_errors: network.total_errors_on_received(),
            tx_errors: network.total_errors_on_transmitted(),
        })
        .collect()
}

fn get_gateways() -> Vec<Gateway> {
    default_net::get_interfaces()
        .into_iter()
        .flat_map(|iface| {
            iface.gateway.map(|gw| Gateway {
                address: gw.ip_addr.to_string(),
            })
        })
        .collect()
}

fn get_dns_servers() -> Vec<String> {
    let mut dns_servers = Vec::new();
    // read /etc/resolv.conf
    let Ok(resolv_conf) = fs::read_to_string("/etc/resolv.conf") else {
        return dns_servers;
    };
    for line in resolv_conf.lines() {
        if line.starts_with("nameserver") {
            let Some(ip) = line.split_whitespace().nth(1) else {
                continue;
            };
            dns_servers.push(ip.to_string());
        }
    }
    dns_servers
}

pub async fn notify_q(event: &str, payload: &str) -> Result<()> {
    let local_config: LocalConfig =
        serde_json::from_str(&fs::read_to_string("/tapp/config.json")?)?;
    let nc = host_api::client::new_client(local_config.host_api_url);
    nc.notify(Notification {
        event: event.to_string(),
        payload: payload.to_string(),
    })
    .await?;
    Ok(())
}

fn run_command(command: &str) -> Result<()> {
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("Command failed: {}", output.status));
    }
    Ok(())
}
