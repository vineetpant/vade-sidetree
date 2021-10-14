use did::{Document, JsonWebKey, PublicKey, Service};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct Delta {
    pub patches: Vec<Patch>,
    pub update_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct SuffixData {
    pub delta_hash: String,
    pub recovery_commitment: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case"))]
pub struct SignedUpdateDataPayload {
    pub delta_hash: String,
    pub update_key: JsonWebKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePublicKeys {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPublicKeys {
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveServices {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddServices {
    pub service_endpoints: Vec<Service>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceDocument {
    pub document: Document,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all(serialize = "kebab-case", deserialize = "kebab-case"))]
pub enum Patch {
    AddPublicKeys(AddPublicKeys),
    RemovePublicKeys(RemovePublicKeys),
    AddServiceEndpoints(AddServices),
    RemoveServiceEndpoints(RemoveServices),
    Replace(ReplaceDocument),
    IetfJsonPatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error<'a> {
    MissingField(&'a str),
    SerializationError,
}

impl fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
pub mod did;
mod encoder;
pub mod multihash;
pub mod operations;
pub mod secp256k1;
