use dstack_rust::dstack_client::DstackClient as AsyncDstackClient;
use evidence_api::tdx::quote::TdxQuote;
use tokio;

#[tokio::test]
async fn test_async_client_get_key() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_key(None, None).await.unwrap();
    assert!(!result.key.is_empty());
    assert_eq!(result.decode_key().unwrap().len(), 32);
}

#[tokio::test]
async fn test_async_client_get_quote() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    assert!(!result.quote.is_empty());
}

#[tokio::test]
async fn test_async_client_get_tls_key() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_tls_key(None, None, false, false, false).await.unwrap();
    assert!(result.key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!result.certificate_chain.is_empty());
}

#[tokio::test]
async fn test_tls_key_uniqueness() {
    let client = AsyncDstackClient::new(None);
    let result1 = client.get_tls_key(None, None, false, false, false).await.unwrap();
    let result2 = client.get_tls_key(None, None, false, false, false).await.unwrap();
    assert_ne!(result1.key, result2.key);
}

#[tokio::test]
async fn test_replay_rtmr() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    let rtmrs = result.replay_rtmrs().unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = TdxQuote::parse_tdx_quote(quote).unwrap();
    assert_eq!(rtmrs[&0], hex::encode(tdx_quote.body.rtmr0));
    assert_eq!(rtmrs[&1], hex::encode(tdx_quote.body.rtmr1));
    assert_eq!(rtmrs[&2], hex::encode(tdx_quote.body.rtmr2));
    assert_eq!(rtmrs[&3], hex::encode(tdx_quote.body.rtmr3));
}

#[tokio::test]
async fn test_report_data() {
    let report_data = "test";
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote(report_data.into()).await.unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = TdxQuote::parse_tdx_quote(quote).unwrap();
    let expected = {
        let mut padded = report_data.as_bytes().to_vec();
        padded.resize(64, 0);
        padded
    };
    assert_eq!(&tdx_quote.body.report_data[..], &expected[..]);
}
