//! Certificate creation functions.

use std::time::SystemTime;
use std::{path::Path, time::Duration};

use anyhow::{anyhow, Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType,
};
use tdx_attest::eventlog::read_event_logs;
use tdx_attest::get_quote;
use x509_parser::der_parser::Oid;
use x509_parser::prelude::X509Certificate;

use crate::attestation::QuoteContentType;
use crate::{
    oids::{PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE},
    traits::CertExt,
};

/// A CA certificate and private key.
pub struct CaCert {
    /// The original PEM certificate.
    pub pem_cert: String,
    /// CA certificate
    pub cert: Certificate,
    /// CA private key
    pub key: KeyPair,
}

impl CaCert {
    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn new(pem_cert: String, pem_key: String) -> Result<Self> {
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert =
            CertificateParams::from_ca_cert_pem(&pem_cert).context("Failed to parse cert")?;
        let todo = "load the cert from the file directly: blocked by https://github.com/rustls/rcgen/issues/274";
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self {
            pem_cert,
            cert,
            key,
        })
    }

    /// Load a CA certificate and private key from files.
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let pem_key = fs::read_to_string(key_path).context("Failed to read key file")?;
        let pem_cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
        Self::new(pem_cert, pem_key)
    }

    /// Sign a certificate request.
    pub fn sign(&self, req: CertRequest) -> Result<Certificate> {
        let key = req.key;
        let params = req.into_cert_params()?;
        let cert = params.signed_by(key, &self.cert, &self.key)?;
        Ok(cert)
    }
}

/// Information required to create a certificate.
#[derive(bon::Builder)]
pub struct CertRequest<'a> {
    key: &'a KeyPair,
    org_name: Option<&'a str>,
    subject: &'a str,
    alt_names: Option<&'a [String]>,
    ca_level: Option<u8>,
    quote: Option<&'a [u8]>,
    event_log: Option<&'a [u8]>,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
}

impl CertRequest<'_> {
    fn into_cert_params(self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        if let Some(org_name) = self.org_name {
            dn.push(DnType::OrganizationName, org_name);
        }
        dn.push(DnType::CommonName, self.subject);
        params.distinguished_name = dn;
        if let Some(alt_names) = self.alt_names {
            for alt_name in alt_names {
                params
                    .subject_alt_names
                    .push(SanType::DnsName(alt_name.clone().try_into()?));
            }
        }
        if let Some(quote) = self.quote {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(quote);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_QUOTE, content);
            params.custom_extensions.push(ext);
        }
        if let Some(event_log) = self.event_log {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(event_log);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_EVENT_LOG, content);
            params.custom_extensions.push(ext);
        }
        if let Some(ca_level) = self.ca_level {
            if ca_level > 0 {
                params.is_ca = IsCa::Ca(BasicConstraints::Constrained(ca_level));
            }
        }
        if let Some(not_before) = self.not_before {
            params.not_before = not_before.into();
        }
        params.not_after = self
            .not_after
            .unwrap_or_else(|| {
                let now = SystemTime::now();
                let day = Duration::from_secs(86400);
                now + day * 365
            })
            .into();
        Ok(params)
    }

    /// Create a self-signed certificate.
    pub fn self_signed(self) -> Result<Certificate> {
        let key = self.key;
        let cert = self.into_cert_params()?.self_signed(key)?;
        Ok(cert)
    }

    /// Create a certificate signed by a given issuer.
    pub fn signed_by(self, issuer: &Certificate, issuer_key: &KeyPair) -> Result<Certificate> {
        let key = self.key;
        let cert = self
            .into_cert_params()?
            .signed_by(key, issuer, issuer_key)?;
        Ok(cert)
    }
}

impl CertExt for Certificate {
    fn get_extension(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let found = self
            .params()
            .custom_extensions
            .iter()
            .find(|ext| ext.oid_components().collect::<Vec<_>>() == oid)
            .map(|ext| ext.content().to_vec());
        Ok(found)
    }
}

impl CertExt for X509Certificate<'_> {
    fn get_extension(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).or(Err(anyhow!("Invalid oid")))?;
        let found = self
            .get_extension_unique(&oid)
            .context("failt to decode der")?
            .map(|ext| ext.value.to_vec());
        Ok(found)
    }
}

/// A key and certificate pair.
pub struct CertPair {
    /// The certificate in PEM format.
    pub cert_pem: String,
    /// The key in PEM format.
    pub key_pem: String,
}

/// Generate a certificate with RA-TLS quote and event log.
pub fn generate_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<CertPair> {
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let (_, quote) = get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok(CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}
