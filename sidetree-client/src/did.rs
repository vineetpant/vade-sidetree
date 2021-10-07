use crate::{
    encoder::encode,
    multihash::{canonicalize, hash, HashAlgorithm},
    SuffixData,
};
use serde::{ser::SerializeSeq, Serialize};

#[derive(Debug, Serialize, Clone)]
pub struct Document {
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<PublicKey>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct PublicKey {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Purpose>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JsonWebKey>,
}

#[derive(Debug, Serialize, Clone, Default)]
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

#[derive(Debug, Serialize, Clone)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

bitflags! {
    pub struct Purpose: u8 {
        const AUTHENTICATION = 0b00001;
        const ASSERTION_METHOD = 0b00010;
        const CAPABILITY_INVOCATION = 0b00100;
        const CAPABILITY_DELEGATION = 0b01000;
        const KEY_AGREEMENT = 0b10000;
    }
}

impl Serialize for Purpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;

        if self.contains(Purpose::ASSERTION_METHOD) {
            seq.serialize_element("assertionMethod")?;
        }
        if self.contains(Purpose::AUTHENTICATION) {
            seq.serialize_element("authentication")?;
        }
        if self.contains(Purpose::CAPABILITY_DELEGATION) {
            seq.serialize_element("capabilityDelegation")?;
        }
        if self.contains(Purpose::CAPABILITY_INVOCATION) {
            seq.serialize_element("capabilityInvocation")?;
        }
        if self.contains(Purpose::KEY_AGREEMENT) {
            seq.serialize_element("keyAgreement")?;
        }

        seq.end()
    }
}

pub(crate) fn compute_unique_suffix(suffix_data: &SuffixData) -> String {
    let suffix_data_buffer = canonicalize(suffix_data).unwrap();
    let multihash = hash(&suffix_data_buffer, HashAlgorithm::Sha256);

    encode(multihash)
}
