use anyhow::{bail, Context, Result};
use std::fmt::Debug;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use tracing::{debug, error, info};

use crate::{config::TlsPassthroughConfig, main_service::AppState};

use sni::extract_sni;

mod sni;

async fn take_sni(stream: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    let mut buffer = vec![0u8; 4096];
    let mut data_len = 0;
    loop {
        // read data from stream
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            break;
        }
        data_len += n;

        if let Some(sni) = extract_sni(&buffer[..data_len]) {
            let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
            debug!("got sni: {sni}");
            buffer.truncate(data_len);
            return Ok((Some(sni), buffer));
        }
    }
    buffer.truncate(data_len);
    Ok((None, buffer))
}

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

async fn handle_connection(mut inbound: TcpStream, state: AppState) -> Result<()> {
    let (sni, buffer) = take_sni(&mut inbound).await.context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };
    handle_connection_inner(inbound, state, &sni, buffer)
        .await
        .with_context(|| format!("error on connection {sni}"))
}

async fn handle_connection_inner(
    mut inbound: TcpStream,
    state: AppState,
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

pub async fn run(
    listen_addr: impl ToSocketAddrs + Debug + Clone,
    app_state: AppState,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr.clone())
        .await
        .with_context(|| format!("failed to bind {listen_addr:?}"))?;
    info!("tcp bridge listening on {listen_addr:?}");

    loop {
        match listener.accept().await {
            Ok((inbound, addr)) => {
                info!("new connection from {addr}");
                let app_state = app_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(inbound, app_state).await {
                        error!("failed to handle connection: {e:?}");
                    }
                });
            }
            Err(e) => {
                error!("failed to accept connection: {e:?}");
            }
        }
    }
}

pub fn start(config: TlsPassthroughConfig, app_state: AppState) -> Result<()> {
    for port in config.listen_ports {
        let address = config.listen_addr.clone();
        let app_state = app_state.clone();
        tokio::spawn(async move {
            if let Err(err) = run((address.clone(), port), app_state).await {
                error!("error on {address}:{port}: {err:?}");
            }
        });
    }
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
