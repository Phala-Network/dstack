use anyhow::{bail, Context, Result};
use clap::Parser;
use fs_err as fs;
use ra_rpc::client::RaClient;
use serde_json::Value;
use std::{collections::BTreeMap, io::Write};
use tproxy_rpc::RegisterCvmRequest;
use tracing::info;

use crate::{
    cmd_gen_ra_cert,
    utils::{
        deserialize_json_file, run_command, run_command_with_stdin, AppCompose, AppKeys,
        LocalConfig,
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

struct Setup<'a> {
    args: &'a TbootArgs,
    local_config: LocalConfig,
    app_compose: AppCompose,
    app_keys: AppKeys,
    encrypted_env: BTreeMap<String, String>,
}

impl<'a> Setup<'a> {
    fn load(args: &'a TbootArgs) -> Result<Self> {
        Ok(Self {
            args,
            local_config: deserialize_json_file(args.resolve("/tapp/config.json"))
                .context("Failed to read config.json")?,
            app_compose: deserialize_json_file(args.resolve("/tapp/app-compose.json"))
                .context("Failed to read app-compose.json")?,
            app_keys: deserialize_json_file(args.resolve("/tapp/appkeys.json"))
                .context("Failed to read appkeys.json")?,
            encrypted_env: deserialize_json_file(args.resolve("/tapp/env.json"))
                .context("Failed to read env.json")?,
        })
    }

    fn resolve(&self, path: &str) -> String {
        self.args.resolve(path)
    }

    async fn setup(&self) -> Result<()> {
        self.prepare_certs()?;
        self.setup_tproxy_net().await?;
        self.setup_docker_registry()?;
        self.setup_docker_account()?;
        self.prepare_docker_compose()?;
        Ok(())
    }

    async fn setup_tproxy_net(&self) -> Result<()> {
        if !self.app_compose.feature_enabled("tproxy-net") {
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
        let tproxy_url = self
            .local_config
            .tproxy_url
            .as_ref()
            .context("Missing tproxy_url")?;

        let url = format!("{}/prpc", tproxy_url);
        let client = RaClient::new_mtls(
            url,
            fs::read_to_string(self.resolve("/etc/tappd/ca.cert"))?,
            fs::read_to_string(self.resolve("/etc/tappd/tls.cert"))?,
            fs::read_to_string(self.resolve("/etc/tappd/tls.key"))?,
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
        fs::create_dir_all(self.resolve("/etc/wireguard"))?;
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
        fs::write(self.resolve("/etc/wireguard/wg0.conf"), config)?;

        info!("Starting WireGuard");
        run_command("wg-quick", &["up", "wg0"]).context("Failed to start WireGuard")?;
        Ok(())
    }

    fn prepare_certs(&self) -> Result<()> {
        info!("Preparing certs");
        if fs::metadata(self.resolve("/etc/tappd")).is_ok() {
            fs::remove_dir_all(self.resolve("/etc/tappd"))?;
        }
        fs::create_dir_all(self.resolve("/etc/tappd"))?;

        if self.app_keys.app_key.is_empty() {
            bail!("Invalid app_key");
        }
        fs::write(
            self.resolve("/etc/tappd/app-ca.key"),
            &self.app_keys.app_key,
        )?;

        let kms_ca_cert = self.resolve("/tapp/certs/ca.cert");
        if fs::metadata(&kms_ca_cert).is_ok() {
            fs::copy(kms_ca_cert, self.resolve("/etc/tappd/ca.cert"))?;
        } else {
            // symbolic link the app-ca.cert to ca.cert
            fs::os::unix::fs::symlink(
                self.resolve("/etc/tappd/app-ca.cert"),
                self.resolve("/etc/tappd/ca.cert"),
            )?;
        }

        let cert_chain_str = self.app_keys.certificate_chain.join("\n");
        fs::write(self.resolve("/etc/tappd/app-ca.cert"), cert_chain_str)?;

        cmd_gen_ra_cert(GenRaCertArgs {
            ca_key: self.resolve("/etc/tappd/app-ca.key").into(),
            ca_cert: self.resolve("/etc/tappd/app-ca.cert").into(),
            cert_path: self.resolve("/etc/tappd/tls.cert").into(),
            key_path: self.resolve("/etc/tappd/tls.key").into(),
        })
        .context("Failed to generate RA cert")?;

        let mut tls_cert = fs::OpenOptions::new()
            .append(true)
            .open(self.resolve("/etc/tappd/tls.cert"))?;
        tls_cert.write_all(&fs::read(self.resolve("/etc/tappd/app-ca.cert"))?)?;
        Ok(())
    }

    fn setup_docker_registry(&self) -> Result<()> {
        info!("Setting up docker registry");
        let registry_url = self
            .app_compose
            .docker_config
            .registry
            .as_deref()
            .unwrap_or_default();
        let registry_url = if registry_url.is_empty() {
            self.local_config
                .docker_registry
                .as_deref()
                .unwrap_or_default()
        } else {
            registry_url
        };
        if registry_url.is_empty() {
            return Ok(());
        }
        info!("Docker registry: {}", registry_url);
        const DAEMON_ENV_FILE: &str = "/etc/docker/daemon.json";
        let mut daemon_env: Value = if fs::metadata(DAEMON_ENV_FILE).is_ok() {
            let daemon_env = fs::read_to_string(DAEMON_ENV_FILE)?;
            serde_json::from_str(&daemon_env).context("Failed to parse daemon.json")?
        } else {
            serde_json::json!({})
        };
        if !daemon_env.is_object() {
            bail!("Invalid daemon.json");
        }
        daemon_env["registry-mirrors"] =
            Value::Array(vec![serde_json::Value::String(registry_url.to_string())]);
        fs::write(DAEMON_ENV_FILE, serde_json::to_string(&daemon_env)?)?;
        Ok(())
    }

    fn setup_docker_account(&self) -> Result<()> {
        info!("Setting up docker account");
        let username = self
            .app_compose
            .docker_config
            .username
            .as_deref()
            .unwrap_or_default();
        if username.is_empty() {
            return Ok(());
        }
        let token_key = self
            .app_compose
            .docker_config
            .token_key
            .as_deref()
            .unwrap_or_default();
        if token_key.is_empty() {
            return Ok(());
        }
        let token = self
            .encrypted_env
            .get(token_key)
            .with_context(|| format!("Missing token for {username}"))?;
        if token.is_empty() {
            bail!("Missing token for {username}");
        }
        run_command("docker", &["login", "-u", username, "-p", token])?;
        Ok(())
    }

    fn prepare_docker_compose(&self) -> Result<()> {
        info!("Preparing docker compose");
        if self.app_compose.runner == "docker-compose" {
            let docker_compose = self
                .app_compose
                .docker_compose_file
                .as_ref()
                .context("Missing docker_compose_file")?;
            fs::write(self.resolve("/tapp/docker-compose.yaml"), docker_compose)?;
        } else {
            bail!("Unsupported runner: {}", self.app_compose.runner);
        }
        Ok(())
    }
}

pub async fn tboot(args: &TbootArgs) -> Result<()> {
    Setup::load(args)?.setup().await?;
    Ok(())
}
