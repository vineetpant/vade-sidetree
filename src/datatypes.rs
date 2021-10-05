use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "snake_case"))]
pub struct OperationRequestGenerated {
    pub r#type: String,
    pub suffix_data: SuffixData,
    pub delta: Delta,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "snake_case"))]
pub struct SuffixData {
    pub delta_hash: String,
    pub recovery_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct Delta {
    pub patches: Vec<Patch>,
    pub update_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "snake_case"))]
pub struct Patch {
    pub action: String,
    pub document: Document,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "snake_case"))]
pub struct Document {
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "snake_case"))]
pub struct PublicKey {
    pub id: String,
    pub public_key_jwk: serde_json::Value,
    purposes: Vec<String>,
    r#type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DIDCreateResult {
    pub operation_request: OperationRequestGenerated,
    pub did_suffix: String,
    pub update_key: serde_json::Value,
    pub recovery_key: serde_json::Value,
    pub signing_key: serde_json::Value,
}

pub struct SideTreeConfig {
    pub sidetree_rest_api_url: String,
}
