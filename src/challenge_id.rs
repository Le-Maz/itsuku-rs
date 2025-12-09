//! This module defines the cryptographic challenge identifier (`I`) used throughout the Itsuku
//! Proof-of-Work (PoW) scheme.

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;

/// Represents the **cryptographic challenge identifier** for a single Proof-of-Work task.
///
/// This identifier is central to the Itsuku scheme, as it is used to personalize the memory
/// content and hash functions, effectively preventing precomputation attacks where a prover
/// calculates expensive memory structures once and uses them for multiple challenges.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengeId {
    #[serde(with = "::serde_with::As::<Base64>")]
    pub bytes: Vec<u8>,
}
