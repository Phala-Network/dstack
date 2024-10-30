use anyhow::{Context, Result};
use std::fmt::Debug;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::debug;

use crate::main_service::AppState;

#[derive(Debug)]
struct TappAddress {
    app_id: String,
    port: u16,
}

impl TappAddress {
    fn parse(data: &[u8]) -> Result<Self> {
        // format: "3327603e03f5bd1f830812ca4a789277fc31f577:555"
        let data = String::from_utf8(data.to_vec()).context("invalid tapp address")?;
        let (app_id, port) = data.split_once(':').context("invalid tapp address")?;
        Ok(Self {
            app_id: app_id.to_string(),
            port: port.parse().context("invalid port")?,
        })
    }
}

/// resolve tapp address by sni
async fn resolve_tapp_address(sni: &str) -> Result<TappAddress> {
    let txt_domain = format!("_tapp-address.{sni}");
    let resolver = hickory_resolver::AsyncResolver::tokio_from_system_conf()
        .context("failed to create dns resolver")?;
    let lookup = resolver
        .txt_lookup(txt_domain)
        .await
        .context("failed to lookup tapp address")?;
    let txt_record = lookup.iter().next().context("no txt record found")?;
    let data = txt_record
        .txt_data()
        .get(0)
        .context("no data in txt record")?;
    TappAddress::parse(data).context("failed to parse tapp address")
}

pub(crate) async fn proxy(
    state: AppState,
    mut inbound: TcpStream,
    sni: &str,
    buffer: Vec<u8>,
) -> Result<()> {
    let tapp_addr = resolve_tapp_address(sni)
        .await
        .context("failed to resolve tapp address")?;
    debug!("target address is {}:{}", tapp_addr.app_id, tapp_addr.port);
    let target_ip = state
        .lock()
        .get_host(&tapp_addr.app_id)
        .context("tapp not found")?
        .ip;
    let mut outbound = TcpStream::connect((target_ip, tapp_addr.port))
        .await
        .context("failed to connect to tapp")?;
    outbound
        .write_all(&buffer)
        .await
        .context("failed to write to tapp")?;

    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("failed to copy between inbound and outbound")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_tapp_address() {
        let tapp_addr =
            resolve_tapp_address("3327603e03f5bd1f830812ca4a789277fc31f577.app.kvin.wang")
                .await
                .unwrap();
        assert_eq!(tapp_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(tapp_addr.port, 8090);
    }
}
