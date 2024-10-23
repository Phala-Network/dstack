use super::*;

async fn new_certbot() -> Result<CertBot> {
    let dns01_client = Dns01Client::new_cloudflare(
        std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID not set"),
        std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set"),
    );
    let credentials =
        std::env::var("LETSENCRYPT_CREDENTIAL").expect("LETSENCRYPT_CREDENTIAL not set");
    CertBot::load(dns01_client, &credentials).await
}

#[tokio::test]
async fn test_request_new_certificates() {
    tracing_subscriber::fmt::try_init().ok();

    let test_domain = std::env::var("TEST_DOMAIN").expect("TEST_DOMAIN not set");
    let bot = new_certbot().await.unwrap();
    println!("account credentials: {}", bot.dump_credentials().unwrap());
    let key = KeyPair::generate().unwrap();
    let key_pem = key.serialize_pem();
    let cert = bot
        .request_new_certificates(&key_pem, &test_domain)
        .await
        .expect("Failed to get cert");
    println!("key:\n{}", key_pem);
    println!("cert:\n{}", cert);
}
