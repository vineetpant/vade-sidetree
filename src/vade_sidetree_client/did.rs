use super::{
    encoder::encode,
    multihash::{canonicalize, hash, HashAlgorithm},
    SuffixData,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<Purpose>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<JsonWebKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct JsonWebKeyPublic {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct JsonWebKey {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum Purpose {
    Authentication,
    KeyAgreement,
    AssertionMethod,
    CapabilityDelegation,
    CapabilityInvocation,
}

pub(crate) fn compute_unique_suffix(suffix_data: &SuffixData) -> String {
    let suffix_data_buffer = match canonicalize(suffix_data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let multihash = hash(&suffix_data_buffer, HashAlgorithm::Sha256);
    encode(multihash)
}
