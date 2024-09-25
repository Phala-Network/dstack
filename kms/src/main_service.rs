use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppKeyResponse,
};
use ra_rpc::RpcCall;
use ra_tls::{
    attestation::Attestation,
    cert::{CaCert, CertRequest},
    kdf::derive_ecdsa_key_pair,
    qvl::quote::{Report, TDReport10},
};
use tracing::info;

use crate::config::{AllowedMr, KmsConfig};

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

struct KmsStateInner {
    config: KmsConfig,
    root_ca: CaCert,
}

impl KmsState {
    fn lock(&self) -> &KmsStateInner {
        &self.inner
    }

    pub fn new(config: KmsConfig) -> Result<Self> {
        let ca_cert = CaCert::load(&config.root_ca_cert, &config.root_ca_key)
            .context("Failed to load root CA certificate")?;
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca: ca_cert,
            }),
        })
    }
}

pub struct RpcHandler {
    state: KmsState,
    attestation: Option<Attestation>,
}

impl AllowedMr {
    pub fn is_allowed(&self, report: &TDReport10) -> bool {
        self.mrtd.contains(&report.mr_td)
            && self.rtmr0.contains(&report.rt_mr0)
            && self.rtmr1.contains(&report.rt_mr1)
            && self.rtmr2.contains(&report.rt_mr2)
    }
}

impl RpcHandler {
    fn ensure_attested(&self) -> Result<&Attestation> {
        let Some(attestation) = &self.attestation else {
            return Err(anyhow::anyhow!("No attestation provided"));
        };
        let quote = attestation.decode_quote()?;

        let report = match quote.report {
            Report::SgxEnclave(_) => bail!("SGX enclave not supported"),
            Report::TD10(r) => r,
            Report::TD15(r) => r.base,
        };
        info!("Incoming report:");
        info!("MRTD: {:?}", hex_fmt::HexFmt(&report.mr_td));
        info!("RTMR0: {:?}", hex_fmt::HexFmt(&report.rt_mr0));
        info!("RTMR1: {:?}", hex_fmt::HexFmt(&report.rt_mr1));
        info!("RTMR2: {:?}", hex_fmt::HexFmt(&report.rt_mr2));
        info!("RTMR3: {:?}", hex_fmt::HexFmt(&report.rt_mr3));

        if !self.state.inner.config.allowed_mr.is_allowed(&report) {
            bail!("Forbidden MR");
        }
        Ok(attestation)
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self) -> Result<AppKeyResponse> {
        let attest = self.ensure_attested()?;
        let app_id = attest.decode_app_id().context("Failed to decode app ID")?;
        let state = self.state.lock();

        let app_key = derive_ecdsa_key_pair(
            &state.root_ca.key,
            &[app_id.as_bytes(), "app-key".as_bytes()],
        )
        .context("Failed to derive app key")?;

        let app_disk_key = derive_ecdsa_key_pair(
            &state.root_ca.key,
            &[app_id.as_bytes(), "app-disk-key".as_bytes()],
        )
        .context("Failed to derive app disk key")?;

        let subject = format!("{app_id}{}", state.config.subject_postfix);
        let req = CertRequest::builder()
            .subject(&subject)
            .ca_level(1)
            .quote(&attest.quote)
            .event_log(&attest.event_log)
            .app_info(&attest.app_info)
            .key(&app_key)
            .build();

        let cert = state
            .root_ca
            .sign(req)
            .context("Failed to sign certificate")?;

        Ok(AppKeyResponse {
            app_key: app_key.serialize_pem(),
            disk_crypt_key: app_disk_key.serialize_pem(),
            certificate_chain: vec![cert.pem(), state.root_ca.cert.pem()],
        })
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        KmsServer::new(self)
    }

    fn construct(state: &KmsState, attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
            attestation,
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}
