use std::sync::Arc;

use anyhow::{bail, Result};
use kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppKeyResponse,
};
use ra_rpc::RpcCall;
use ra_tls::{
    attestation::Attestation,
    qvl::quote::{Report, TDReport10},
};

use crate::config::{AllowedMr, KmsConfig};

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

struct KmsStateInner {
    config: KmsConfig,
}

impl KmsState {
    pub fn new(config: KmsConfig) -> Self {
        Self {
            inner: Arc::new(KmsStateInner { config }),
        }
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
            && self.rtmr3.contains(&report.rt_mr3)
    }
}

#[derive(Debug)]
struct AttestedInfo {
    mrtd: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
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

        if !self.state.inner.config.allowed_mr.is_allowed(&report) {
            bail!("Forbidden MR");
        }
        Ok(attestation)
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self) -> Result<AppKeyResponse> {
        let attest = self.ensure_attested()?;
        Ok(AppKeyResponse {
            app_key: "example app key".to_string(),
            disk_crypt_key: "example disk crypt key".to_string(),
            certificate_chain: "example chain".to_string(),
            comment: hex::encode(&attest.quote),
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
