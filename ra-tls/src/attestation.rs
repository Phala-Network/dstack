//! Attestation functions

use anyhow::{anyhow, Context, Result};
use dcap_qvl::quote::Quote;
use qvl::{quote::Report, verify::VerifiedReport};
use sha2::{Digest, Sha384};

use crate::{oids, traits::CertExt};
use cc_eventlog::TdxEventLog as EventLog;

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
    /// App defined data
    AppData,
}

impl QuoteContentType {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
            Self::AppData => "app-data",
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        use sha2::Digest;
        // The format is:
        // sha2_512(<tag>:<content>)
        let mut hasher = sha2::Sha512::new();
        hasher.update(self.tag().as_bytes());
        hasher.update(b":");
        hasher.update(content);
        hasher.finalize().into()
    }
}

/// Attestation data
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Quote
    pub quote: Vec<u8>,
    /// Raw event log
    pub raw_event_log: Vec<u8>,
    /// Event log
    pub event_log: Vec<EventLog>,
    /// Verified report
    pub verified_report: Option<VerifiedReport>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(quote: Vec<u8>, raw_event_log: Vec<u8>) -> Result<Self> {
        let event_log: Vec<EventLog> = if !raw_event_log.is_empty() {
            serde_json::from_slice(&raw_event_log).context("invalid event log")?
        } else {
            vec![]
        };
        Ok(Self {
            quote,
            raw_event_log,
            event_log,
            verified_report: None,
        })
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
        let raw_event_log = read_ext_bytes!(oids::PHALA_RATLS_EVENT_LOG).unwrap_or_default();
        Self::new(quote, raw_event_log).map(Some)
    }

    /// Decode the quote
    pub fn decode_quote(&self) -> Result<Quote> {
        Quote::parse(&self.quote)
    }

    fn find_event(&self, imr: u32, ad: &str) -> Result<EventLog> {
        for event in &self.event_log {
            if event.imr == imr && event.event == ad {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {ad} not found"))
    }

    /// Replay event logs
    pub fn replay_event_logs(&self) -> Result<[[u8; 48]; 4]> {
        replay_event_logs(&self.event_log)
    }

    /// Return true if the quote is verified
    pub fn is_verified(&self) -> bool {
        self.verified_report.is_some()
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event(3, "instance-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_upgraded_app_id(&self) -> Result<String> {
        self.find_event(3, "upgraded-app-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event(3, "rootfs-hash")
            .map(|event| hex::encode(&event.digest))
    }

    /// Decode the report data in the quote
    pub fn decode_report_data(&self) -> Result<[u8; 64]> {
        match self.decode_quote()?.report {
            Report::SgxEnclave(report) => Ok(report.report_data),
            Report::TD10(report) => Ok(report.report_data),
            Report::TD15(report) => Ok(report.base.report_data),
        }
    }

    /// Ensure the quote is for the RA-TLS public key
    pub fn ensure_quote_for_ra_tls_pubkey(&self, pubkey: &[u8]) -> Result<()> {
        let report_data = self.decode_report_data()?;
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
        if report_data != expected_report_data {
            return Err(anyhow!("report data mismatch"));
        }
        Ok(())
    }
}

/// Replay event logs
pub fn replay_event_logs(eventlog: &[EventLog]) -> Result<[[u8; 48]; 4]> {
    let mut rtmrs = [[0u8; 48]; 4];
    for idx in 0..4 {
        let mut mr = [0u8; 48];

        for event in eventlog.iter() {
            if event.imr == idx {
                let mut hasher = Sha384::new();
                hasher.update(&mr);
                hasher.update(&event.digest);
                mr = hasher.finalize().into();
            }
        }

        rtmrs[idx as usize] = mr;
    }

    Ok(rtmrs)
}
