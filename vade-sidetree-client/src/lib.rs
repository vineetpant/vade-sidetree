use did::{Document, JsonWebKey, JsonWebKeyPublic, PublicKey, Service};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// `Delta` represents a set of changes to be applied to a document, such as a DID Document.
/// This struct stores the data needed to describe the delta, including the patches to be
/// applied and the update commitment.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{Delta, Patch};
///
/// let patch = Patch::default(); // Replace with an actual patch
/// let delta = Delta {
///     patches: vec![patch],
///     update_commitment: "commitment-value".to_string(),
/// };
/// ```
///
/// # Fields
/// * `patches`: A vector of `Patch` structs, each representing a change to be applied to the document.
/// * `update_commitment`: A string representing the commitment value associated with the update.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    pub patches: Vec<Patch>,
    pub update_commitment: String,
}

/// `SuffixData` represents the information needed to identify a unique instance of a document,
/// such as a DID Document, within the Sidetree protocol.
///
/// This struct stores the data required to construct a unique suffix for the document, including
/// the delta hash and the recovery commitment.
///
/// # Examples
///
/// ```
/// use vade_sidetree::SuffixData;
///
/// let suffix_data = SuffixData {
///     delta_hash: "hash-value".to_string(),
///     recovery_commitment: "commitment-value".to_string(),
/// };
/// ```
///
/// # Fields
/// * `delta_hash`: A string representing the hash of the delta to be applied to the document.
/// * `recovery_commitment`: A string representing the commitment value associated with the recovery mechanism.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SuffixData {
    pub delta_hash: String,
    pub recovery_commitment: String,
}

/// `SignedUpdateDataPayload` represents the payload that is used to sign an update operation
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for signing the update operation, including the
/// delta hash and the update key.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{SignedUpdateDataPayload, JsonWebKey};
///
/// let update_key = JsonWebKey::default(); // Replace with an actual key
/// let signed_update_data_payload = SignedUpdateDataPayload {
///     delta_hash: "hash-value".to_string(),
///     update_key,
/// };
/// ```
///
/// # Fields
/// * `delta_hash`: A string representing the hash of the delta to be applied to the document.
/// * `update_key`: A `JsonWebKey` representing the update key associated with the update operation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedUpdateDataPayload {
    pub delta_hash: String,
    pub update_key: JsonWebKey,
}

/// `SignedRecoveryDataPayload` represents the payload that is used to sign a recovery operation
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for signing the recovery operation, including the
/// delta hash, the public recovery key, and the recovery commitment.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{SignedRecoveryDataPayload, JsonWebKeyPublic};
///
/// let recovery_key = JsonWebKeyPublic::default(); // Replace with an actual key
/// let signed_recovery_data_payload = SignedRecoveryDataPayload {
///     delta_hash: "hash-value".to_string(),
///     recovery_key,
///     recovery_commitment: "commitment-value".to_string(),
/// };
/// ```
///
/// # Fields
/// * `delta_hash`: A string representing the hash of the delta to be applied to the document.
/// * `recovery_key`: A `JsonWebKeyPublic` representing the public recovery key associated with the recovery operation.
/// * `recovery_commitment`: A string representing the commitment value associated with the recovery mechanism.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedRecoveryDataPayload {
    pub delta_hash: String,
    pub recovery_key: JsonWebKeyPublic,
    pub recovery_commitment: String,
}

/// `SignedDeactivateDataPayload` represents the payload that is used to sign a deactivate operation
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for signing the deactivate operation, including the
/// DID suffix and the public recovery key.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{SignedDeactivateDataPayload, JsonWebKeyPublic};
///
/// let recovery_key = JsonWebKeyPublic::default(); // Replace with an actual key
/// let signed_deactivate_data_payload = SignedDeactivateDataPayload {
///     did_suffix: "suffix-value".to_string(),
///     recovery_key,
/// };
/// ```
///
/// # Fields
/// * `did_suffix`: A string representing the unique identifier of the DID document to be deactivated.
/// * `recovery_key`: A `JsonWebKeyPublic` representing the public recovery key associated with the deactivate operation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedDeactivateDataPayload {
    pub did_suffix: String,
    pub recovery_key: JsonWebKeyPublic,
}

/// `RemovePublicKeys` represents an action to remove a set of public keys from a DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for removing public keys, including a vector of
/// public key IDs.
///
/// # Examples
///
/// ```
/// use vade_sidetree::RemovePublicKeys;
///
/// let remove_public_keys = RemovePublicKeys {
///     ids: vec!["key-id-1".to_string(), "key-id-2".to_string()],
/// };
/// ```
///
/// # Fields
/// * `ids`: A vector of strings representing the IDs of the public keys to be removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePublicKeys {
    pub ids: Vec<String>,
}

/// `AddPublicKeys` represents an action to add a set of public keys to a DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for adding public keys, including a vector of
/// `PublicKey` instances.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{AddPublicKeys, PublicKey};
///
/// let public_key1 = PublicKey::default(); // Replace with an actual key
/// let public_key2 = PublicKey::default(); // Replace with an actual key
/// let add_public_keys = AddPublicKeys {
///     public_keys: vec![public_key1, public_key2],
/// };
/// ```
///
/// # Fields
/// * `public_keys`: A vector of `PublicKey` instances representing the public keys to be added to the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPublicKeys {
    pub public_keys: Vec<PublicKey>,
}

/// `RemoveServices` represents an action to remove a set of services from a DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for removing services, including a vector of
/// service IDs.
///
/// # Examples
///
/// ```
/// use vade_sidetree::RemoveServices;
///
/// let remove_services = RemoveServices {
///     ids: vec!["service-id-1".to_string(), "service-id-2".to_string()],
/// };
/// ```
///
/// # Fields
/// * `ids`: A vector of strings representing the IDs of the services to be removed from the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveServices {
    pub ids: Vec<String>,
}

/// `AddServices` represents an action to add a set of services to a DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for adding services, including a vector of
/// `Service` instances.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{AddServices, Service};
///
/// let service1 = Service::default(); // Replace with an actual service
/// let service2 = Service::default(); // Replace with an actual service
/// let add_services = AddServices {
///     services: vec![service1, service2],
/// };
/// ```
///
/// # Fields
/// * `services`: A vector of `Service` instances representing the services to be added to the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddServices {
    pub services: Vec<Service>,
}

/// `ReplaceDocument` represents an action to replace the entire DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for replacing the DID document, including
/// a `Document` instance.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{ReplaceDocument, Document};
///
/// let document = Document::default(); // Replace with an actual document
/// let replace_document = ReplaceDocument {
///     document,
/// };
/// ```
///
/// # Fields
/// * `document`: A `Document` instance representing the new DID document that will replace the current one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceDocument {
    pub document: Document,
}

/// `JsonPatch` represents a collection of JSON patches to be applied to a DID document
/// within the Sidetree protocol.
///
/// This struct stores the necessary data for applying JSON patches, including a vector of
/// `IetfJsonPatch` instances.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{JsonPatch, IetfJsonPatch};
///
/// let patch1 = IetfJsonPatch::default(); // Replace with an actual patch
/// let patch2 = IetfJsonPatch::default(); // Replace with an actual patch
/// let json_patch = JsonPatch {
///     patches: vec![patch1, patch2],
/// };
/// ```
///
/// # Fields
/// * `patches`: A vector of `IetfJsonPatch` instances representing the JSON patches to be applied to the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatch {
    pub patches: Vec<IetfJsonPatch>,
}

/// `IetfJsonPatch` represents an individual JSON patch operation following the IETF JSON
/// Patch standard (RFC 6902) for use within the Sidetree protocol.
///
/// This struct stores the necessary data for applying a JSON patch, including the operation,
/// path, and value.
///
/// # Examples
///
/// ```
/// use vade_sidetree::{IetfJsonPatch, Value};
///
/// let json_patch = IetfJsonPatch {
///     op: "replace".to_string(),
///     path: "/publicKeys/0".to_string(),
///     value: Value::String("new_public_key".to_string()),
/// };
/// ```
///
/// # Fields
/// * `op`: A string representing the JSON patch operation (e.g., "add", "remove", "replace", "move", "copy", or "test").
/// * `path`: A string representing the JSON Pointer path of the target location for the patch operation.
/// * `value`: A `Value` instance representing the value to be used in the patch operation, when applicable.

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
pub mod did;
mod encoder;
pub mod multihash;
pub mod operations;
pub mod secp256k1;
