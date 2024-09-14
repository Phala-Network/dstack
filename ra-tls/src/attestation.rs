//! Attestation functions

use anyhow::Result;
use dcap_qvl::quote::Quote;

use crate::{oids, traits::CertExt};

/// Attestation data
pub struct Attestation {
    /// Quote
    pub quote: Vec<u8>,
    /// Event log
    pub event_log: Vec<u8>,
    /// Application info
    pub app_info: Vec<u8>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(quote: Vec<u8>, event_log: Vec<u8>, app_info: Vec<u8>) -> Self {
        Self {
            quote,
            event_log,
            app_info,
        }
    }

    /// Extract attestation data from a certificate
    pub fn from_cert(cert: &impl CertExt) -> Result<Option<Self>> {
        Self::from_ext_getter(|oid| cert.get_extension(oid))
    }

    /// From an extension getter
    pub fn from_ext_getter(
        get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
    ) -> Result<Option<Self>> {
        macro_rules! read_ext_bytes {
            ($oid:expr) => {
                get_ext($oid)?
                    .map(|v| yasna::parse_der(&v, |reader| reader.read_bytes()))
                    .transpose()?
            };
        }

        let quote = match read_ext_bytes!(oids::PHALA_RATLS_QUOTE) {
            Some(v) => v,
            None => return Ok(None),
        };
        let event_log = read_ext_bytes!(oids::PHALA_RATLS_EVENT_LOG).unwrap_or_default();
        let app_info = read_ext_bytes!(oids::PHALA_RATLS_APP_INFO).unwrap_or_default();

        Ok(Some(Self {
            quote,
            event_log,
            app_info,
        }))
    }

    /// Decode the quote
    pub fn decode_quote(&self) -> Result<Quote> {
        Quote::parse(&self.quote)
    }
}
