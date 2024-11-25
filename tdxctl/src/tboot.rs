use anyhow::{bail, Context, Result};
use clap::Parser;
use fs_err as fs;
use ra_rpc::client::RaClient;
use std::io::Write;
use tproxy_rpc::RegisterCvmRequest;
use tracing::info;

use crate::{
    cmd_gen_ra_cert,
    utils::{
        deserialize_json_file, run_command, run_command_with_stdin, AppCompose, AppKeys, VmConfig,
    },
    GenRaCertArgs,
};

#[derive(Parser)]
/// Boot the Tapp
pub(crate) struct TbootArgs {
    /// shutdown if the tboot fails
    #[arg(long)]
    pub(crate) shutdown_on_fail: bool,
    /// Source directory
    #[arg(short, long, default_value = "")]
    prefix: String,
}

impl TbootArgs {
    pub(crate) fn resolve(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

fn prepare_docker_compose(args: &TbootArgs, compose: &AppCompose) -> Result<()> {
    info!("Preparing docker compose");
    if compose.runner == "docker-compose" {
        let docker_compose = compose
            .docker_compose_file
            .as_ref()
            .context("Missing docker_compose_file")?;
        fs::write(args.resolve("/tapp/docker-compose.yaml"), docker_compose)?;
    } else {
        bail!("Unsupported runner: {}", compose.runner);
    }
    Ok(())
}

async fn setup_tproxy_net(args: &TbootArgs, compose: &AppCompose) -> Result<()> {
    if !compose.feature_enabled("tproxy-net") {
        info!("tproxy is not enabled");
        return Ok(());
    }
    info!("Setting up tproxy network");
    // Generate WireGuard keys
    let sk = run_command("wg", &["genkey"])?;
    let sk = String::from_utf8(sk).context("Failed to parse client private key")?;
    let sk = sk.trim();
    let pk = run_command_with_stdin("wg", &["pubkey"], &sk)?;
    let pk = String::from_utf8(pk).context("Failed to parse client public key")?;
    let pk = pk.trim();

    // Read config and make API call
    let config: VmConfig = deserialize_json_file(args.resolve("/tapp/config.json"))?;
    let tproxy_url = config.tproxy_url.as_ref().context("Missing tproxy_url")?;

    let url = format!("{}/prpc", tproxy_url);
    let client = RaClient::new_mtls(
        url,
        fs::read_to_string(args.resolve("/etc/tappd/ca.cert"))?,
        fs::read_to_string(args.resolve("/etc/tappd/tls.cert"))?,
        fs::read_to_string(args.resolve("/etc/tappd/tls.key"))?,
    )?;
    let tproxy_client = tproxy_rpc::tproxy_client::TproxyClient::new(client);
    let response = tproxy_client
        .register_cvm(RegisterCvmRequest {
            client_public_key: pk.to_string(),
        })
        .await
        .context("Failed to register CVM")?;
    let wg_info = response.wg.context("Missing wg info")?;
    let _tappd_info = response.tappd.context("Missing tappd info")?;

    let client_ip = &wg_info.client_ip;
    let server_endpoint = &wg_info.server_endpoint;
    let server_public_key = &wg_info.server_public_key;
    let server_ip = &wg_info.server_ip;

    info!("WG CLIENT_IP: {}", client_ip);
    info!("WG SERVER_ENDPOINT: {}", server_endpoint);
    info!("WG SERVER_PUBLIC_KEY: {}", server_public_key);
    info!("WG SERVER_IP: {}", server_ip);

    // Create WireGuard config
    fs::create_dir_all(args.resolve("/etc/wireguard"))?;
    let config = format!(
        "[Interface]\n\
        PrivateKey = {sk}\n\
        Address = {client_ip}/24\n\n\
        [Peer]\n\
        PublicKey = {server_public_key}\n\
        AllowedIPs = {server_ip}/24\n\
        Endpoint = {server_endpoint}\n\
        PersistentKeepalive = 25\n"
    );
    fs::write(args.resolve("/etc/wireguard/wg0.conf"), config)?;

    info!("Starting WireGuard");
    run_command("wg-quick", &["up", "wg0"]).context("Failed to start WireGuard")?;
    Ok(())
}

fn prepare_certs(args: &TbootArgs) -> Result<()> {
    info!("Preparing certs");
    fs::create_dir_all(args.resolve("/etc/tappd"))?;

    let appkeys_data = fs::read_to_string(args.resolve("/tapp/appkeys.json"))?;
    let appkeys: AppKeys = serde_json::from_str(&appkeys_data)?;

    if appkeys.app_key.is_empty() {
        bail!("Invalid app_key");
    }
    fs::write(args.resolve("/etc/tappd/app-ca.key"), &appkeys.app_key)?;

    let kms_ca_cert = args.resolve("/tapp/certs/ca.cert");
    if fs::metadata(&kms_ca_cert).is_ok() {
        fs::copy(kms_ca_cert, args.resolve("/etc/tappd/ca.cert"))?;
    } else {
        // symbolic link the app-ca.cert to ca.cert
        fs::os::unix::fs::symlink(
            args.resolve("/etc/tappd/app-ca.cert"),
            args.resolve("/etc/tappd/ca.cert"),
        )?;
    }

    let cert_chain_str = appkeys.certificate_chain.join("\n");
    fs::write(args.resolve("/etc/tappd/app-ca.cert"), cert_chain_str)?;

    cmd_gen_ra_cert(GenRaCertArgs {
        ca_key: args.resolve("/etc/tappd/app-ca.key").into(),
        ca_cert: args.resolve("/etc/tappd/app-ca.cert").into(),
        cert_path: args.resolve("/etc/tappd/tls.cert").into(),
        key_path: args.resolve("/etc/tappd/tls.key").into(),
    })
    .context("Failed to generate RA cert")?;

    let mut tls_cert = fs::OpenOptions::new()
        .append(true)
        .open(args.resolve("/etc/tappd/tls.cert"))?;
    tls_cert.write_all(&fs::read(args.resolve("/etc/tappd/app-ca.cert"))?)?;
    Ok(())
}

pub async fn tboot(args: &TbootArgs) -> Result<()> {
    let compose: AppCompose = deserialize_json_file(args.resolve("/tapp/app-compose.json"))
        .context("Failed to read compose file")?;
    prepare_certs(args)?;
    setup_tproxy_net(args, &compose).await?;
    prepare_docker_compose(args, &compose)?;
    Ok(())
}
