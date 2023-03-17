pub mod did;
mod encoder;
pub mod multihash;
pub mod operations;
pub mod secp256k1;

use did::{Document, JsonWebKey, JsonWebKeyPublic, PublicKey, Service};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    pub patches: Vec<Patch>,
    pub update_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SuffixData {
    pub delta_hash: String,
    pub recovery_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedUpdateDataPayload {
    pub delta_hash: String,
    pub update_key: JsonWebKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedRecoveryDataPayload {
    pub delta_hash: String,
    pub recovery_key: JsonWebKeyPublic,
    pub recovery_commitment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedDeactivateDataPayload {
    pub did_suffix: String,
    pub recovery_key: JsonWebKeyPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePublicKeys {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPublicKeys {
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveServices {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddServices {
    pub services: Vec<Service>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceDocument {
    pub document: Document,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatch {
    pub patches: Vec<IetfJsonPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IetfJsonPatch {
    pub op: String,
    pub path: String,
    pub value: Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all(serialize = "kebab-case", deserialize = "kebab-case"))]
pub enum Patch {
    AddPublicKeys(AddPublicKeys),
    RemovePublicKeys(RemovePublicKeys),
    AddServices(AddServices),
    RemoveServices(RemoveServices),
    Replace(ReplaceDocument),
    IetfJsonPatch(JsonPatch),
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

