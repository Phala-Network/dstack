use anyhow::{bail, Context, Result};
use clap::Parser;
use ra_rpc::client::RaClient;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use tproxy_rpc::tproxy_client::TproxyClient;
use tracing::{error, info};
use x509_parser::prelude::*;

const BASE_URL: &str = "https://crt.sh";

struct Monitor {
    tproxy_uri: String,
    domain: String,
    known_keys: BTreeSet<Vec<u8>>,
    last_checked: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CTLog {
    id: u64,
    issuer_ca_id: u64,
    issuer_name: String,
    common_name: String,
    name_value: String,
    not_before: String,
    not_after: String,
    serial_number: String,
    result_count: u64,
    entry_timestamp: String,
}

impl Monitor {
    fn new(tproxy_uri: String, domain: String) -> Result<Self> {
        validate_domain(&domain)?;
        Ok(Self {
            tproxy_uri,
            domain,
            known_keys: BTreeSet::new(),
            last_checked: None,
        })
    }

    async fn refresh_known_keys(&mut self) -> Result<()> {
        info!("Refreshing known keys...");
        let todo = "Use RA-TLS";
        let tls_no_check = true;
        let rpc = TproxyClient::new(RaClient::no_check(self.tproxy_uri.clone(), tls_no_check));
        let info = rpc.acme_info().await?;
        self.known_keys = info.hist_keys.into_iter().collect();
        info!("Got {} known keys", self.known_keys.len());
        Ok(())
    }

    async fn get_logs(&self, count: u32) -> Result<Vec<CTLog>> {
        let url = format!(
            "{}/?q={}&output=json&limit={}",
            BASE_URL, self.domain, count
        );
        let response = reqwest::get(&url).await?;
        Ok(response.json().await?)
    }

    async fn check_one_log(&self, log: &CTLog) -> Result<()> {
        let cert_url = format!("{}/?d={}", BASE_URL, log.id);
        let cert_data = reqwest::get(&cert_url).await?.text().await?;

        let pem = Pem::iter_from_buffer(cert_data.as_bytes())
            .next()
            .transpose()
            .context("failed to parse pem")?
            .context("empty pem")?;
        let cert = pem.parse_x509().context("invalid x509 certificate")?;

        let pubkey = cert.public_key().raw;
        if !self.known_keys.contains(pubkey) {
            error!("Error in {:?}", log);
            bail!(
                "certificate has issued to unknown pubkey: {:?}",
                hex_fmt::HexFmt(pubkey)
            );
        }
        info!("known pubkey: {:?}", hex_fmt::HexFmt(pubkey));
        Ok(())
    }

    async fn check_new_logs(&mut self) -> Result<()> {
        let logs = self.get_logs(10000).await?;
        info!("num logs: {}", logs.len());

        for log in logs.iter() {
            let log_id = log.id;
            info!("log id={}", log_id);

            if let Some(last_checked) = self.last_checked {
                if log_id <= last_checked {
                    break;
                }
            }

            self.check_one_log(log).await?;
        }

        if !logs.is_empty() {
            let last_log = &logs[0];
            info!("last checked: {}", last_log.id);
            self.last_checked = Some(last_log.id);
        }

        Ok(())
    }

    async fn run(&mut self) {
        info!("Monitoring {}...", self.domain);
        loop {
            if let Err(err) = self.refresh_known_keys().await {
                error!("Error refreshing known keys: {}", err);
            }
            if let Err(err) = self.check_new_logs().await {
                error!("Error: {}", err);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    let domain_regex =
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap();
    if !domain_regex.is_match(domain) {
        bail!("Invalid domain name");
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// TProxy URI
    #[arg(short, long)]
    tproxy_uri: String,
    /// Domain name to monitor
    #[arg(short, long)]
    domain: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let mut monitor = Monitor::new(args.tproxy_uri, args.domain)?;
    monitor.run().await;
    Ok(())
}
