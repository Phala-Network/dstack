use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::dns01_client::Record;

use super::Dns01Api;

const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareClient {
    zone_id: String,
    api_token: String,
}

impl CloudflareClient {
    pub fn new(zone_id: String, api_token: String) -> Self {
        Self { zone_id, api_token }
    }
}

impl Dns01Api for CloudflareClient {
    async fn add_txt_record(&self, domain: &str, content: &str) -> Result<String> {
        let client = Client::new();
        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_URL, self.zone_id);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&json!({
                "type": "TXT",
                "name": domain,
                "content": content,
                "ttl": 120
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "failed to create acme challenge: {}",
                response.text().await?
            );
        }

        #[derive(Deserialize)]
        struct Response {
            result: ApiResult,
        }

        #[derive(Deserialize)]
        struct ApiResult {
            id: String,
        }

        let response: Response = response.json().await.context("failed to parse response")?;

        Ok(response.result.id)
    }

    async fn remove_record(&self, record_id: &str) -> Result<()> {
        let client = Client::new();
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_URL, self.zone_id, record_id
        );

        let response = client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "failed to remove acme challenge: {}",
                response.text().await?
            );
        }

        Ok(())
    }

    async fn remove_txt_records(&self, challenge_domain: &str) -> Result<()> {
        for record in self.get_txt_records(challenge_domain).await? {
            self.remove_record(&record.id).await?;
        }
        Ok(())
    }

    async fn get_txt_records(&self, domain: &str) -> Result<Vec<Record>> {
        let client = Client::new();
        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_URL, self.zone_id);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("failed to get dns records: {}", response.text().await?);
        }

        #[derive(Deserialize, Debug)]
        struct CloudflareResponse {
            result: Vec<Record>,
        }

        let response: CloudflareResponse =
            response.json().await.context("failed to parse response")?;

        let records = response
            .result
            .into_iter()
            .filter(|record| record.name == domain && record.r#type == "TXT")
            .collect();
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dns01_client::Dns01Client;

    fn create_client() -> Dns01Client {
        Dns01Client::new_cloudflare(
            std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID not set"),
            std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set"),
        )
    }

    fn random_subdomain() -> String {
        format!(
            "_acme-challenge.{}.kvin.wang",
            rand::random::<u64>().to_string()
        )
    }

    #[tokio::test]
    async fn it_works() {
        let client = create_client();
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890")
            .await
            .unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert_eq!(record[0].id, record_id);
        assert_eq!(record[0].content, "1234567890");
        client.remove_record(&record_id).await.unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert!(record.is_empty());
    }

    #[tokio::test]
    async fn it_can_remove_by_identifier() {
        let client = create_client();
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890")
            .await
            .unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert_eq!(record[0].id, record_id);
        assert_eq!(record[0].content, "1234567890");
        client.remove_txt_records(&subdomain).await.unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert!(record.is_empty());
    }
}
