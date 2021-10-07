use did::{Document, PublicKey, Service};
use serde::{ser::SerializeMap, Serialize};
#[macro_use]
extern crate bitflags;

#[derive(Debug, Serialize, Clone)]
pub struct Delta {
    patches: Vec<Patch>,
    update_commitment: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct SuffixData {
    #[serde(rename = "deltaHash")]
    delta_hash: String,
    #[serde(rename = "recoveryCommitment")]
    recovery_commitment: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    data_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Patch {
    AddPublicKeys(Vec<PublicKey>),
    RemovePublicKeys(Vec<String>),
    AddServices(Vec<Service>),
    RemoveServices(Vec<String>),
    Replace(Document),
    IetfJsonPatch,
}

impl Serialize for Patch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        match self {
            Patch::AddPublicKeys(public_keys) => {
                map.serialize_entry("action", "add-public-keys")?;
                map.serialize_entry("publicKeys", public_keys)?;
            }
            Patch::RemovePublicKeys(_) => {}
            Patch::AddServices(_) => {}
            Patch::RemoveServices(_) => {}
            Patch::Replace(document) => {
                map.serialize_entry("action", "replace")?;
                map.serialize_entry("document", document)?;
            }
            Patch::IetfJsonPatch => {}
        }

        map.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error<'a> {
    MissingField(&'a str),
    SerializationError,
}

mod did;
mod encoder;
mod multihash;
pub mod operations;
pub mod secp256k1;
