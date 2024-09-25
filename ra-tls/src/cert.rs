//! Certificate creation functions.

use anyhow::{Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType,
};

use crate::{
    oids::{PHALA_RATLS_APP_INFO, PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE},
    traits::CertExt,
};

/// A CA certificate and private key.
pub struct CaCert {
    /// CA certificate
    pub cert: Certificate,
    /// CA private key
    pub key: KeyPair,
}

impl CaCert {
    /// Load a CA certificate and private key from files.
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        let pem_key = fs::read_to_string(key_path).context("Failed to read key file")?;
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
        let cert = CertificateParams::from_ca_cert_pem(&cert).context("Failed to parse cert")?;
        let todo = "load the cert from the file directly: blocked by https://github.com/rustls/rcgen/issues/274";
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self { cert, key })
    }

    /// Sign a certificate request.
    pub fn sign(&self, req: CertRequest) -> Result<Certificate> {
        let key = req.key;
        let params = req.into_cert_params()?;
        let cert = params.signed_by(&key, &self.cert, &self.key)?;
        Ok(cert)
    }
}

/// Information required to create a certificate.
#[derive(bon::Builder)]
pub struct CertRequest<'a> {
    key: &'a KeyPair,
    org_name: Option<&'a str>,
    subject: &'a str,
    alt_subject: Option<&'a str>,
    ca_level: Option<u8>,
    quote: Option<&'a [u8]>,
    event_log: Option<&'a [u8]>,
    app_info: Option<&'a [u8]>,
}

impl<'a> CertRequest<'a> {
    fn into_cert_params(self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        if let Some(org_name) = self.org_name {
            dn.push(DnType::OrganizationName, org_name);
        }
        dn.push(DnType::CommonName, self.subject);
        params.distinguished_name = dn;
        if let Some(alt_subject) = self.alt_subject {
            params
                .subject_alt_names
                .push(SanType::DnsName(alt_subject.try_into()?));
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
        if let Some(app_info) = self.app_info {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(app_info);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_APP_INFO, content);
            params.custom_extensions.push(ext);
        }
        if let Some(ca_level) = self.ca_level {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(ca_level));
        }
        Ok(params)
    }

    /// Create a self-signed certificate.
    pub fn self_signed(self) -> Result<Certificate> {
        let key = self.key;
        let cert = self.into_cert_params()?.self_signed(key)?;
        Ok(cert)
    }

    /// Create a certificate signed by a given issuer.
    pub fn signed_by(
        self,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> Result<Certificate> {
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
