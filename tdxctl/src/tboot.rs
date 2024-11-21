use anyhow::{bail, Context, Result};
use fs_err as fs;
use std::io::Write;
use tproxy_rpc::RegisterCvmResponse;
use tracing::info;

use crate::{
    cmd_gen_ra_cert,
    utils::{
        deserialize_json_file, run_command, run_command_with_stdin, AppCompose, AppKeys, VmConfig,
    },
    GenRaCertArgs,
};

fn prepare_docker_compose(compose: &AppCompose) -> Result<()> {
    info!("Preparing docker compose");
    if compose.runner == "docker-compose" {
        let docker_compose = compose
            .docker_compose_file
            .as_ref()
            .context("Missing docker_compose_file")?;
        fs::write("/tapp/docker-compose.yaml", docker_compose)?;
    } else {
        bail!("Unsupported runner: {}", compose.runner);
    }
    Ok(())
}

fn setup_tproxy_net(compose: &AppCompose) -> Result<()> {
    if !compose.feature_enabled("tproxy-net") {
        info!("tproxy is not enabled");
        return Ok(());
    }
    info!("Setting up tproxy network");
    // Generate WireGuard keys
    let client_private_key = run_command("wg", &["genkey"])?;
    let client_private_key =
        String::from_utf8(client_private_key).context("Failed to parse client private key")?;
    let client_private_key = client_private_key.trim();
    let client_public_key = run_command_with_stdin("wg", &["pubkey"], &client_private_key)?;
    let client_public_key =
        String::from_utf8(client_public_key).context("Failed to parse client public key")?;
    let client_public_key = client_public_key.trim();

    // Read config and make API call
    let config: VmConfig = deserialize_json_file("/tapp/config.json")?;
    let tproxy_url = config.tproxy_url.as_ref().context("Missing tproxy_url")?;

    let url = format!("{}/prpc/Tproxy.RegisterCvm?json", tproxy_url);
    let body = serde_json::to_string(&serde_json::json!({
        "client_public_key": client_public_key
    }))?;
    let todo = "Use rust library";
    let output = run_command(
        "curl",
        &[
            "--cacert",
            "/etc/tappd/ca.cert",
            "--cert",
            "/etc/tappd/tls.cert",
            "--key",
            "/etc/tappd/tls.key",
            "-d",
            &body,
            &url,
        ],
    )?;
    let response: RegisterCvmResponse =
        serde_json::from_slice(&output).context("Failed to parse response")?;

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
    fs::create_dir_all("/etc/wireguard")?;
    let config = format!(
        "[Interface]\n\
        PrivateKey = {client_private_key}\n\
        Address = {client_ip}/24\n\n\
        [Peer]\n\
        PublicKey = {server_public_key}\n\
        AllowedIPs = {server_ip}/24\n\
        Endpoint = {server_endpoint}\n\
        PersistentKeepalive = 25\n"
    );
    fs::write("/etc/wireguard/wg0.conf", config)?;

    info!("Starting WireGuard");
    run_command("wg-quick", &["up", "wg0"]).context("Failed to start WireGuard")?;
    Ok(())
}

fn prepare_certs() -> Result<()> {
    info!("Preparing certs");
    fs::create_dir_all("/etc/tappd")?;
    fs::copy("/tapp/certs/ca.cert", "/etc/tappd/ca.cert")?;

    let appkeys_data = fs::read_to_string("/tapp/appkeys.json")?;
    let appkeys: AppKeys = serde_json::from_str(&appkeys_data)?;

    if appkeys.app_key.is_empty() {
        bail!("Invalid app_key");
    }
    fs::write("/etc/tappd/app-ca.key", &appkeys.app_key)?;

    let cert_chain_str = appkeys.certificate_chain.join("\n");
    fs::write("/etc/tappd/app-ca.cert", cert_chain_str)?;

    cmd_gen_ra_cert(GenRaCertArgs {
        ca_key: "/etc/tappd/app-ca.key".into(),
        ca_cert: "/etc/tappd/app-ca.cert".into(),
        cert_path: "/etc/tappd/tls.cert".into(),
        key_path: "/etc/tappd/tls.key".into(),
    })
    .context("Failed to generate RA cert")?;

    let mut tls_cert = fs::OpenOptions::new()
        .append(true)
        .open("/etc/tappd/tls.cert")?;
    tls_cert.write_all(&fs::read("/etc/tappd/app-ca.cert")?)?;
    Ok(())
}

pub fn tboot() -> Result<()> {
    let compose: AppCompose =
        deserialize_json_file("/tapp/app-compose.json").context("Failed to read compose file")?;
    prepare_certs()?;
    setup_tproxy_net(&compose)?;
    prepare_docker_compose(&compose)?;
    Ok(())
}
