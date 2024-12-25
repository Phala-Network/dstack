use crate::utils::{deserialize_json_file, LocalConfig};
use anyhow::{anyhow, Result};
use host_api::{
    client::{new_client, DefaultClient},
    Notification,
};
use tracing::warn;

pub(crate) struct NotifyClient {
    client: DefaultClient,
}

impl Default for NotifyClient {
    fn default() -> Self {
        Self::new("".into())
    }
}

impl NotifyClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: new_client(base_url),
        }
    }

    pub fn load_or_default(url: Option<String>) -> Result<Self> {
        let url = match url {
            Some(url) => url,
            None => {
                let local_config: LocalConfig = deserialize_json_file("/tapp/config.json")?;
                local_config.host_api_url.clone()
            }
        };
        Ok(Self::new(url))
    }

    pub async fn notify(&self, event: &str, payload: &str) -> Result<()> {
        self.client
            .notify(Notification {
                event: event.to_string(),
                payload: payload.to_string(),
            })
            .await?;
        Ok(())
    }

    pub async fn notify_q(&self, event: &str, payload: &str) {
        if let Err(err) = self.notify(event, payload).await {
            warn!("Failed to notify event {event} to host: {:?}", err);
        }
    }

    pub async fn get_sealing_key(&self, quote: &[u8]) -> Result<host_api::GetSealingKeyResponse> {
        self.client
            .get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            })
            .await
            .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))
    }
}
