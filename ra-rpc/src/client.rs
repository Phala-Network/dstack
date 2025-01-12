use std::time::Duration;

use anyhow::{bail, Context, Result};
use prpc::{
    client::{Error, RequestClient},
    Message,
};
use ra_tls::attestation::{Attestation, VerifiedAttestation};
use reqwest::{tls::TlsInfo, Certificate, Client, Identity, Response};
use serde::{de::DeserializeOwned, Serialize};

use bon::Builder;

type AttestationValidator =
    Box<dyn Fn(Option<VerifiedAttestation>) -> Result<()> + Send + Sync + 'static>;

#[derive(Builder)]
pub struct RaClientConfig {
    remote_uri: String,
    #[builder(default = false)]
    tls_no_check: bool,
    tls_client_cert: Option<String>,
    tls_client_key: Option<String>,
    tls_ca_cert: Option<String>,
    #[builder(default = true)]
    tls_built_in_root_certs: bool,
    pccs_url: Option<String>,
    attestation_validator: Option<AttestationValidator>,
}

impl RaClientConfig {
    pub fn into_client(self) -> Result<RaClient> {
        let mut builder = Client::builder()
            .tls_sni(true)
            .danger_accept_invalid_certs(self.tls_no_check)
            .tls_built_in_root_certs(self.tls_built_in_root_certs)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60));
        if self.attestation_validator.is_some() {
            builder = builder.tls_info(true);
        }
        if let (Some(cert_pem), Some(key_pem)) = (self.tls_client_cert, self.tls_client_key) {
            let identity_pem = format!("{cert_pem}\n{key_pem}");
            let identity =
                Identity::from_pem(identity_pem.as_bytes()).context("Failed to parse identity")?;
            builder = builder.identity(identity);
        }
        if let Some(ca) = self.tls_ca_cert {
            let ca = Certificate::from_pem(ca.as_bytes()).context("Failed to parse CA")?;
            builder = builder.add_root_certificate(ca);
        }
        let client = builder.build().context("failed to create client")?;
        Ok(RaClient {
            remote_uri: self.remote_uri,
            pccs_url: self.pccs_url,
            client,
            attestation_validator: self.attestation_validator,
        })
    }
}

pub struct RaClient {
    remote_uri: String,
    pccs_url: Option<String>,
    client: Client,
    attestation_validator: Option<AttestationValidator>,
}

impl RaClient {
    pub fn new(remote_uri: String, tls_no_check: bool) -> Result<Self> {
        RaClientConfig::builder()
            .tls_no_check(tls_no_check)
            .remote_uri(remote_uri)
            .build()
            .into_client()
            .context("failed to create client")
    }

    pub fn new_mtls(remote_uri: String, cert_pem: String, key_pem: String) -> Result<Self> {
        RaClientConfig::builder()
            .tls_no_check(true)
            .tls_built_in_root_certs(false)
            .remote_uri(remote_uri)
            .tls_client_cert(cert_pem)
            .tls_client_key(key_pem)
            .build()
            .into_client()
            .context("failed to create client")
    }

    async fn try_validate_attestation(&self, response: &Response) -> Result<()> {
        let Some(validator) = &self.attestation_validator else {
            return Ok(());
        };

        let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
            bail!("No TLS info in response");
        };
        let Some(cert) = tls_info.peer_certificate() else {
            return validator(None);
        };
        let (_, cert) =
            x509_parser::parse_x509_certificate(cert).context("Failed to parse certificate")?;

        let Some(attestation) =
            Attestation::from_cert(&cert).context("Failed to parse attestation")?
        else {
            return validator(None);
        };

        let verified_attestation = attestation
            .verify_with_ra_pubkey(cert.public_key().raw, self.pccs_url.as_deref())
            .await
            .context("Failed to verify the attestation report")?;

        validator(Some(verified_attestation))
    }
}

impl RequestClient for RaClient {
    async fn request<T, R>(&self, path: &str, body: T) -> Result<R, Error>
    where
        T: Message + Serialize,
        R: Message + DeserializeOwned,
    {
        let body = serde_json::to_vec(&body).context("Failed to serialize body")?;
        let url = format!("{}/{}?json", self.remote_uri, path);
        let response = self
            .client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|err| Error::RpcError(format!("failed to send request: {:?}", err)))?;

        self.try_validate_attestation(&response)
            .await
            .context("Failed to validate attestation")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::RpcError(format!(
                "request failed with status={status}, error={body}",
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|err| Error::RpcError(format!("failed to read response: {:?}", err)))?
            .to_vec();
        let response = serde_json::from_slice(&body).context("Failed to deserialize response")?;
        Ok(response)
    }
}
