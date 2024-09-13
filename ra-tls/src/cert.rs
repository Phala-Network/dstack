//! Certificate creation functions.

use anyhow::Result;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType,
};

use crate::oids::{PHALA_RATLS_APP_INFO, PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE};

/// Information required to create a certificate.
#[bon::builder]
pub struct CertRequest<'a> {
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
            params.subject_alt_names.push(SanType::DnsName(alt_subject.try_into()?));
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
    pub fn self_signed(self, key_pair: &KeyPair) -> Result<Certificate> {
        let cert = self.into_cert_params()?.self_signed(key_pair)?;
        Ok(cert)
    }

    /// Create a certificate signed by a given issuer.
    pub fn signed_by(
        self,
        key: &KeyPair,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> Result<Certificate> {
        let cert = self
            .into_cert_params()?
            .signed_by(key, issuer, issuer_key)?;
        Ok(cert)
    }
}
