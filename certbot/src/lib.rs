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

pub use acme_client::AcmeClient;
pub use dns01_client::Dns01Client;
pub use bot::{CertBot, CertBotConfig};

mod acme_client;
mod dns01_client;
mod bot;
