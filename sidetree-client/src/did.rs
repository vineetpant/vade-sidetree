use crate::{
    encoder::encode,
    multihash::{canonicalize, hash, HashAlgorithm},
    SuffixData,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Document {
    pub public_keys: Vec<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PublicKey {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Vec<Purpose>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JsonWebKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JsonWebKey {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub enum Purpose {
    Auth,
    Assertion,
    Invocation,
    Delegation,
    Agreement,
}

pub(crate) fn compute_unique_suffix(suffix_data: &SuffixData) -> String {
    let suffix_data_buffer = match canonicalize(suffix_data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let multihash = hash(&suffix_data_buffer, HashAlgorithm::Sha256);
    encode(multihash)
}
