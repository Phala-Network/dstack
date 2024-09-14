//! Traits for the crate

use anyhow::Result;

/// Types that can get custom cert extensions from.
pub trait CertExt {
    /// Get a cert extension from the type.
    fn get_extension(&self, oid: &[u64]) -> Result<Option<Vec<u8>>>;
}
