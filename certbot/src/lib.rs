//! A CertBot client for requesting certificates from Let's Encrypt.
//!
//! This library provides a simple interface for requesting and managing SSL/TLS certificates
//! using the ACME protocol with Let's Encrypt as the Certificate Authority.
//!
//! # Features
//!
//! - Automatic certificate issuance and renewal
//! - DNS-01 challenge support (currently implemented for Cloudflare)
//! - Easy integration with existing Rust applications
//!
//! # Usage
//!
//! To use this library, you'll need to create a `CertBot` instance with your DNS provider
//! credentials and ACME account information. Then, you can use the `request_new_certificates`
//! method to obtain new certificates for your domains.
//!
//! ```rust
//! use certbot::{CertBot, Dns01Client};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let dns01_client = Dns01Client::new_cloudflare(
//!         "your_cloudflare_zone_id",
//!         "your_cloudflare_api_token",
//!     );
//!
//!     let certbot = CertBot::load(dns01_client, "your_acme_account_credentials").await?;
//!
//!     let key_pair = KeyPair::generate()?;
//!     let key_pem = key_pair.serialize_pem();
//!     let cert = certbot.request_new_certificates(&key_pem, "example.com").await?;
//!
//!     println!("New certificate obtained: {}", cert);
//!     Ok(())
//! }
//! ```
//!
//! For more detailed information on the available methods and their usage, please refer
//! to the documentation of individual structs and functions.
use std::time::Duration;

use anyhow::{Context, Result};
use dns01_client::Dns01Api;
use hickory_resolver::error::ResolveErrorKind;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{debug, error};

pub use dns01_client::Dns01Client;

mod dns01_client;

/// A CertBot instance.
pub struct CertBot {
    account: Account,
    credentials: AccountCredentials,
    dns01_client: Dns01Client,
}

#[derive(Debug, Clone)]
struct Challenge {
    id: String,
    acme_domain: String,
    identifier: String,
    url: String,
    dns_value: String,
}

impl CertBot {
    pub async fn load(dns01_client: Dns01Client, encoded_credentials: &str) -> Result<Self> {
        let credentials: AccountCredentials = serde_json::from_str(&encoded_credentials)?;
        let account = Account::from_credentials(credentials).await?;
        let credentials: AccountCredentials = serde_json::from_str(&encoded_credentials)?;
        Ok(Self {
            account,
            dns01_client,
            credentials,
        })
    }

    /// Create a new account.
    pub async fn new_account(acme_url: &str, dns01_client: Dns01Client) -> Result<Self> {
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme_url,
            None,
        )
        .await
        .context("failed to create new account")?;
        Ok(Self {
            account,
            dns01_client,
            credentials,
        })
    }

    /// Dump the account credentials to a JSON string.
    pub fn dump_credentials(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.credentials)?)
    }

    /// Read the account ID from the encoded credentials.
    pub fn account_id(&self) -> String {
        let todo = "read id from instant_acme::Account";
        let encoded_credentials = self.dump_credentials().expect("failed to dump credentials");
        read_account_id(&encoded_credentials).expect("failed to read account ID")
    }

    /// Request new certificates for the given domain.
    ///
    /// Returns the new certificates encoded in PEM format.
    pub async fn request_new_certificates(&self, key: &str, domain: &str) -> Result<String> {
        let mut challenges = Vec::new();
        let result = self
            .request_new_certificates_inner(key, domain, &mut challenges)
            .await;
        for challenge in &challenges {
            debug!("removing dns record {}", challenge.id);
            if let Err(err) = self.dns01_client.remove_record(&challenge.id).await {
                error!("failed to remove dns record {}: {err}", challenge.id);
            }
        }
        result
    }
}

impl CertBot {
    async fn authorize(&self, order: &mut Order, challenges: &mut Vec<Challenge>) -> Result<()> {
        let authorizations = order
            .authorizations()
            .await
            .context("failed to get authorizations")?;
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => anyhow::bail!("unsupported authorization status: {:?}", authz.status),
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .context("no dns01 challenge found")?;

            let Identifier::Dns(identifier) = &authz.identifier;

            let dns_value = order.key_authorization(challenge).dns_value();
            debug!("creating dns record for {}", identifier);
            let acme_domain = format!("_acme-challenge.{identifier}");
            self.dns01_client
                .remove_txt_records(&acme_domain)
                .await
                .context("failed to remove existing dns record")?;
            let id = self
                .dns01_client
                .add_txt_record(&acme_domain, &dns_value)
                .await
                .context("failed to create dns record")?;
            challenges.push(Challenge {
                id,
                acme_domain,
                identifier: identifier.clone(),
                url: challenge.url.clone(),
                dns_value,
            });
        }
        Ok(())
    }

    /// Self check the TXT records for the given challenges.
    async fn check_dns(&self, challenges: &[Challenge]) -> Result<()> {
        let mut delay = Duration::from_millis(250);
        let mut tries = 1u8;

        let mut unsettled_challenges = challenges.to_vec();

        'outer: loop {
            use hickory_resolver::AsyncResolver;

            sleep(delay).await;

            let dns_resolver =
                AsyncResolver::tokio_from_system_conf().context("failed to create dns resolver")?;

            while let Some(challenge) = unsettled_challenges.pop() {
                let settled = match dns_resolver.txt_lookup(&challenge.acme_domain).await {
                    Ok(record) => record
                        .iter()
                        .find(|txt| txt.to_string() == challenge.dns_value)
                        .is_some(),
                    Err(err) => {
                        let ResolveErrorKind::NoRecordsFound { .. } = err.kind() else {
                            anyhow::bail!(
                                "failed to lookup dns record {}: {err}",
                                challenge.acme_domain
                            );
                        };
                        false
                    }
                };
                if !settled {
                    delay *= 2;
                    tries += 1;
                    if tries < 10 {
                        debug!(
                            tries,
                            domain = &challenge.acme_domain,
                            "challenge not found, waiting {delay:?}"
                        );
                    } else {
                        anyhow::bail!("dns record not found");
                    }
                    unsettled_challenges.push(challenge);
                    continue 'outer;
                }
            }
            break;
        }
        Ok(())
    }

    async fn request_new_certificates_inner(
        &self,
        key: &str,
        domain: &str,
        challenges: &mut Vec<Challenge>,
    ) -> Result<String> {
        debug!("requesting new certificates for {}", domain);
        debug!("creating new order");
        let names = vec![domain.to_string()];
        let identifiers = names
            .iter()
            .map(|name| Identifier::Dns(name.clone()))
            .collect::<Vec<_>>();
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("failed to cread new order")?;
        let mut challenges_ready = false;
        loop {
            order.refresh().await.context("failed to refresh order")?;
            match order.state().status {
                // Need to accept the challenge
                OrderStatus::Pending => {
                    if challenges_ready {
                        debug!("challenges are ready, waiting for order to be ready");
                        sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    debug!("order is pending, waiting for authorization");
                    self.authorize(&mut order, challenges)
                        .await
                        .context("failed to authorize")?;
                    self.check_dns(challenges)
                        .await
                        .context("failed to check dns")?;
                    for challenge in &*challenges {
                        debug!("setting challenge ready for {}", challenge.url);
                        order
                            .set_challenge_ready(&challenge.url)
                            .await
                            .context("failed to set challenge ready")?;
                    }
                    challenges_ready = true;
                    continue;
                }
                // To upload CSR
                OrderStatus::Ready => {
                    debug!("order is ready, uploading csr");
                    let csr = make_csr(key, &names)?;
                    order
                        .finalize(csr.as_ref())
                        .await
                        .context("failed to finalize order")?;
                    continue;
                }
                // Need to wait for the challenge to be accepted
                OrderStatus::Processing => {
                    debug!("order is processing, waiting for challenge to be accepted");
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                // Certificate is ready
                OrderStatus::Valid => {
                    debug!("order is valid, getting certificate");
                    return extract_certificate(order).await;
                }
                // Something went wrong
                OrderStatus::Invalid => anyhow::bail!("order is invalid"),
            }
        }
    }
}

fn make_csr(key: &str, names: &[String]) -> Result<Vec<u8>> {
    let mut params =
        CertificateParams::new(names).context("failed to create certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    let key = KeyPair::from_pem(key).context("failed to parse private key")?;
    let csr = params
        .serialize_request(&key)
        .context("failed to serialize certificate request")?;
    Ok(csr.der().as_ref().to_vec())
}

async fn extract_certificate(mut order: Order) -> Result<String> {
    let mut tries = 0;
    let cert_chain_pem = loop {
        tries += 1;
        if tries > 5 {
            anyhow::bail!("failed to get certificate");
        }
        match order
            .certificate()
            .await
            .context("failed to get certificate")?
        {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };
    Ok(cert_chain_pem)
}

/// Read the account ID from the encoded credentials. This is a workaround for
/// instant_acme::AccountCredentials::id not being public.
fn read_account_id(encoded_credentials: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct IdInfo {
        id: String,
    }
    let credentials: IdInfo = serde_json::from_str(encoded_credentials)?;
    Ok(credentials.id)
}

#[cfg(test)]
mod tests;
