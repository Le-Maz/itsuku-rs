use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengeId {
    #[serde_as(as = "Base64")]
    pub bytes: Vec<u8>,
}
