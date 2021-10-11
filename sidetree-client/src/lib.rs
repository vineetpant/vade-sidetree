use did::{Document, PublicKey, Service};
use serde::{Serialize, Deserialize};
#[macro_use]
extern crate bitflags;

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
#[serde(tag = "action", content = "public_keys")]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub enum Patch {
    AddPublicKeys(Vec<PublicKey>),
    RemovePublicKeys(Vec<String>),
    AddServices(Vec<Service>),
    RemoveServices(Vec<String>),
    Replace(Document),
    IetfJsonPatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error<'a> {
    MissingField(&'a str),
    SerializationError,
}

pub mod did;
mod encoder;
pub mod multihash;
pub mod operations;
pub mod secp256k1;
