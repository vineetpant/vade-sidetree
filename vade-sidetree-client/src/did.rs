use crate::{
    encoder::encode,
    multihash::{canonicalize, hash, HashAlgorithm},
    SuffixData,
};
use serde::{Deserialize, Serialize};

/// `Document` represents a generic document containing public keys and services. This struct
/// stores the data needed to describe the document, including public keys and services, and is
/// used in various contexts like DID Documents and other data structures.
///
/// # Examples
///
/// ```
/// use vade-sidetree::Document;
/// use vade-sidetree::PublicKey;
/// use vade-sidetree::Service;
///
/// let document = Document {
///     public_keys: Some(vec![PublicKey { /* your PublicKey struct fields */ }]),
///     services: Some(vec![Service { /* your Service struct fields */ }]),
/// };
/// ```
///
/// # Fields
/// * `public_keys`: An optional vector of `PublicKey` structs representing the public keys
///   associated with the document. This field will be skipped during serialization if it is `None`.
/// * `services`: An optional vector of `Service` structs representing the services associated with
///   the document. This field will be skipped during serialization if it is `None`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

/// `PublicKey` represents a public key associated with a document, such as a DID Document.
/// This struct stores the data needed to describe the public key, including its ID, controller,
/// key type, purposes, and the public key itself as a JsonWebKey.
///
/// # Examples
///
/// ```
/// use vade-sidetree::PublicKey;
/// use vade-sidetree::Purpose;
/// use vade-sidetree::JsonWebKey;
///
/// let public_key = PublicKey {
///     id: "public-key-1".to_string(),
///     controller: Some("controller-id".to_string()),
///     key_type: "Ed25519VerificationKey2018".to_string(),
///     purposes: Some(vec![Purpose::Auth]),
///     public_key_jwk: Some(JsonWebKey { /* your JsonWebKey struct fields */ }),
/// };
/// ```
///
/// # Fields
/// * `id`: A string representing the unique identifier of the public key within the document.
/// * `controller`: An optional string representing the identifier of the entity controlling the
///   public key. This field will be skipped during serialization if it is `None`.
/// * `key_type`: A string representing the type of the public key (e.g., "Ed25519VerificationKey2018").
/// * `purposes`: An optional vector of `Purpose` enum variants representing the purposes for which
///   the public key is intended to be used. This field will be skipped during serialization if it is `None`.
/// * `public_key_jwk`: An optional `JsonWebKey` struct representing the public key. This field
///   will be skipped during serialization if it is `None`.
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

/// `JsonWebKeyPublic` represents a public portion of a JsonWebKey (JWK), which is a JSON
/// data structure representing cryptographic keys. This struct stores the data needed to
/// describe the public key, including its key type, curve, x and y coordinates, and an optional nonce.
///
/// # Examples
///
/// ```
/// use vade-sidetree::JsonWebKeyPublic;
///
/// let public_key = JsonWebKeyPublic {
///     key_type: "EC".to_string(),
///     curve: "P-256".to_string(),
///     x: "x-coordinate".to_string(),
///     y: Some("y-coordinate".to_string()),
///     nonce: Some("nonce".to_string()),
/// };
/// ```
///
/// # Fields
/// * `key_type`: A string representing the type of the key (e.g., "EC" for elliptic curve keys).
/// * `curve`: A string representing the curve used for the key (e.g., "P-256" for the NIST P-256 curve).
/// * `x`: A string representing the x-coordinate of the public key point.
/// * `y`: An optional string representing the y-coordinate of the public key point. This field
///   will be skipped during serialization if it is `None`.
/// * `nonce`: An optional string representing a nonce that can be used for key-specific purposes.
///   This field will be skipped during serialization if it is `None`.
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

/// `JsonWebKey` represents a JsonWebKey (JWK), which is a JSON data structure for representing
/// cryptographic keys. This struct stores the data needed to describe the key, including its key
/// type, curve, x and y coordinates, an optional private key component (d), and an optional nonce.
///
/// # Examples
///
/// ```
/// use vade-sidetree::JsonWebKey;
///
/// let jwk = JsonWebKey {
///     key_type: "EC".to_string(),
///     curve: "P-256".to_string(),
///     x: "x-coordinate".to_string(),
///     y: Some("y-coordinate".to_string()),
///     d: Some("private-key-component".to_string()),
///     nonce: Some("nonce".to_string()),
/// };
/// ```
///
/// # Fields
/// * `key_type`: A string representing the type of the key (e.g., "EC" for elliptic curve keys).
/// * `curve`: A string representing the curve used for the key (e.g., "P-256" for the NIST P-256 curve).
/// * `x`: A string representing the x-coordinate of the key point.
/// * `y`: An optional string representing the y-coordinate of the key point. This field
///   will be skipped during serialization if it is `None`.
/// * `d`: An optional string representing the private key component. This field will be skipped
///   during serialization if it is `None`.
/// * `nonce`: An optional string representing a nonce that can be used for key-specific purposes.
///   This field will be skipped during serialization if it is `None`.
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

/// `Service` represents a service associated with a document, such as a DID Document.
/// This struct stores the data needed to describe the service, including its ID,
/// service type, and service endpoint.
///
/// # Examples
///
/// ```
/// use vade-sidetree::Service;
///
/// let service = Service {
///     id: "service-1".to_string(),
///     service_type: "MyService".to_string(),
///     service_endpoint: "https://example.com/my-service".to_string(),
/// };
/// ```
///
/// # Fields
/// * `id`: A string representing the unique identifier of the service within the document.
/// * `service_type`: A string representing the type of the service (e.g., "MyService").
/// * `service_endpoint`: A string representing the URL of the service endpoint.
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
