use std::sync::Arc;

use anyhow::{Context, Result};
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use ra_tls::{cert::CertRequest, kdf::derive_ecdsa_key_pair, rcgen};
use rcgen::{Certificate, CertificateParams, KeyPair};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    DeriveKeyArgs, DeriveKeyResponse, TdxQuoteArgs, TdxQuoteResponse,
};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    key: KeyPair,
    cert: Certificate,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self> {
        let pem_key = fs::read_to_string(&config.key_file).context("Failed to read key file")?;
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert = fs::read_to_string(&config.cert_file).context("Failed to read cert file")?;
        let cert = CertificateParams::from_ca_cert_pem(&cert).context("Failed to parse cert")?;
        let todo = "load the cert from the file directly: blocked by https://github.com/rustls/rcgen/issues/274";
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self {
            inner: Arc::new(AppStateInner { key, cert }),
        })
    }
}

pub struct RpcHandler {
    state: AppState,
}

impl TappdRpc for RpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        let derived_key = derive_ecdsa_key_pair(&self.state.inner.key, &[request.path.as_bytes()])
            .context("Failed to derive key")?;
        let cert = CertRequest::builder()
            .subject(&request.subject)
            .build()
            .signed_by(&derived_key, &self.state.inner.cert, &self.state.inner.key)
            .context("Failed to build certificate request")?;
        Ok(DeriveKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain: vec![cert.pem(), self.state.inner.cert.pem()],
        })
    }

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let todo = "add the event log to the response";
        let todo = "define the report data format";
        let report_data = sha2_512(&request.report_data);
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
        Ok(TdxQuoteResponse {
            quote,
            event_log: Default::default(),
        })
    }
}

impl RpcCall<AppState> for RpcHandler {
    type PrpcService = TappdServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TappdServer::new(self)
    }

    fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <TappdServer<RpcHandler>>::supported_methods()
}

fn sha2_512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}
