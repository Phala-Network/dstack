//! Event log structures

use serde::{Deserialize, Serialize};

/// Event log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    /// the RTMR index
    pub imr: u32,
    /// the event type
    pub event_type: u32,
    /// the hash of the event
    pub digest: String,
    /// the associated data
    pub associated_data: String,
}
