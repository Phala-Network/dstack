use anyhow::Result;
use cloudflare::CloudflareClient;
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

mod cloudflare;

#[derive(Debug, Deserialize, Serialize)]
/// Represents a DNS record
pub(crate) struct Record {
    /// Unique identifier for the record
    pub id: String,
    /// The name of the DNS record (e.g., "_acme-challenge.example.com")
    pub name: String,
    /// The content of the DNS record (e.g., the TXT value for ACME challenges)
    pub content: String,
    /// The type of DNS record (e.g., "TXT" for ACME challenges)
    pub r#type: String,
}

#[enum_dispatch]
pub(crate) trait Dns01Api {
    /// Creates a TXT DNS record with the given domain and content.
    ///
    /// Returns the ID of the created record.
    async fn add_txt_record(&self, domain: &str, content: &str) -> Result<String>;

    /// Remove a DNS record.
    ///
    /// Deletes a DNS record using its unique identifier.
    async fn remove_record(&self, record_id: &str) -> Result<()>;

    /// Remove TXT DNS records by domain.
    ///
    /// Deletes all TXT DNS records matching the given domain.
    async fn remove_txt_records(&self, domain: &str) -> Result<()>;

    /// Get TXT DNS records.
    ///
    /// Retrieves all TXT DNS records matching the given domain.
    async fn get_txt_records(&self, domain: &str) -> Result<Vec<Record>>;
}

/// A DNS-01 client.
#[derive(Debug, Serialize, Deserialize)]
#[enum_dispatch(Dns01Api)]
#[serde(rename_all = "lowercase")]
pub enum Dns01Client {
    Cloudflare(CloudflareClient),
}

impl Dns01Client {
    pub fn new_cloudflare(zone_id: String, api_token: String) -> Self {
        Self::Cloudflare(CloudflareClient::new(zone_id, api_token))
    }
}
