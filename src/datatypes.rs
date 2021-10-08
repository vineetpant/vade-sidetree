use serde::{Deserialize, Serialize};
use sidetree_client::{Delta,SuffixData};

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
    pub update_key: serde_json::Value,
    pub recovery_key: serde_json::Value,
}

pub struct SideTreeConfig {
    pub sidetree_rest_api_url: String,
}
