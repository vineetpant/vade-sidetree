use serde::{Deserialize, Serialize};
use sidetree_client::{
    did::{JsonWebKey, PublicKey},
    Delta, SuffixData,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct OperationRequestGenerated {
    pub r#type: String,
    pub suffix_data: SuffixData,
    pub delta: Delta,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DIDCreateResult {
    pub operation_request: OperationRequestGenerated,
    pub did_suffix: String,
    pub update_key: JsonWebKey,
    pub recovery_key: JsonWebKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedDataPayload {
    pub update_key: JsonWebKey,
    pub delta_hash: String,
}

pub struct SideTreeConfig {
    pub sidetree_rest_api_url: String,
}
