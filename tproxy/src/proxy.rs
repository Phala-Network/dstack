use std::sync::Arc;

use anyhow::{bail, Context, Result};
use sni::extract_sni;
use tls_terminate::TlsTerminateProxy;
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info};

use crate::{config::ProxyConfig, main_service::AppState};

mod sni;
mod tls_passthough;
mod tls_terminate;

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

fn is_subdomain(sni: &str, base_domain: &str) -> bool {
    sni.ends_with(base_domain)
}

async fn handle_connection(
    mut inbound: TcpStream,
    state: AppState,
    dotted_base_domain: &str,
    tls_terminate_proxy: Arc<TlsTerminateProxy>,
) -> Result<()> {
    let (sni, buffer) = take_sni(&mut inbound).await.context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };
    if is_subdomain(&sni, dotted_base_domain) {
        tls_terminate_proxy
            .proxy(inbound, &sni, buffer)
            .await
            .with_context(|| format!("error on connection {sni}"))
    } else {
        tls_passthough::proxy(state, inbound, &sni, buffer)
            .await
            .with_context(|| format!("error on connection {sni}"))
    }
}

pub async fn run(config: &ProxyConfig, app_state: AppState) -> Result<()> {
    let dotted_base_domain = {
        let base_domain = config.base_domain.as_str();
        let base_domain = base_domain.strip_prefix(".").unwrap_or(base_domain);
        Arc::new(format!(".{base_domain}"))
    };

    let tls_terminate_proxy = TlsTerminateProxy::new(
        &app_state,
        &dotted_base_domain,
        &config.cert_chain,
        &config.cert_key,
    )
    .context("failed to create tls terminate proxy")?;
    let tls_terminate_proxy = Arc::new(tls_terminate_proxy);

    let listener = TcpListener::bind((config.listen_addr.clone(), config.listen_port))
        .await
        .with_context(|| {
            format!(
                "failed to bind {}:{}",
                config.listen_addr, config.listen_port
            )
        })?;
    info!(
        "tcp bridge listening on {}:{}",
        config.listen_addr, config.listen_port
    );

    loop {
        match listener.accept().await {
            Ok((inbound, addr)) => {
                info!("new connection from {addr}");
                let app_state = app_state.clone();
                let dotted_base_domain = dotted_base_domain.clone();
                let tls_terminate_proxy = tls_terminate_proxy.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        inbound,
                        app_state,
                        &dotted_base_domain,
                        tls_terminate_proxy,
                    )
                    .await
                    {
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

pub fn start(config: ProxyConfig, app_state: AppState) {
    tokio::spawn(async move {
        if let Err(err) = run(&config, app_state).await {
            error!(
                "error on {}:{}: {err:?}",
                config.listen_addr, config.listen_port
            );
        }
    });
}
