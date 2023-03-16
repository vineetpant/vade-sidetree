use std::collections::HashMap;

#[cfg(feature = "sdk")]
use crate::in3_request_list::ResolveHttpRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "sdk")]
use std::os::raw::c_void;

pub use vade_sidetree_client::{did::*, *};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all(serialize = "camelCase", deserialize = "camelCase"))]
pub enum UpdateType {
    Update,
    Recovery,
    Deactivate,
}
/// `OperationRequestGenerated` represents a generated operation request in the Vade Sidetree system.
/// This struct is used to store the data needed to create a Sidetree operation request, such as
/// creating, updating, or recovering a DID.
///
/// # Examples
///
/// ```
/// use vade-sidetree::OperationRequestGenerated;
/// use vade-sidetree::SuffixData;
/// use vade-sidetree::Delta;
///
/// let operation_request = OperationRequestGenerated {
///     r#type: "create".to_string(),
///     suffix_data: SuffixData { /* your SuffixData struct fields */ },
///     delta: Delta { /* your Delta struct fields */ },
/// };
/// ```
///
/// # Fields
/// * `r#type`: The type of Sidetree operation, e.g., "create", "update", or "recover".
/// * `suffix_data`: Contains the unique identifier data for the DID, such as the commitment and
///   the reveal value.
/// * `delta`: Holds the data for updating the DID document, including patches and the update
///   commitment.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OperationRequestGenerated {
    pub r#type: String,
    pub suffix_data: SuffixData,
    pub delta: Delta,
}

/// `DIDCreateResult` represents the result of a DID (Decentralized Identifier) creation
/// operation in the Vade Sidetree system. This struct stores the data needed to manage the
/// newly created DID, such as the operation request, DID suffix, and the update and recovery keys.
///
/// # Examples
///
/// ```
/// use vade-sidetree::DIDCreateResult;
/// use vade-sidetree::OperationRequestGenerated;
/// use vade-sidetree::JsonWebKey;
///
/// let did_create_result = DIDCreateResult {
///     operation_request: OperationRequestGenerated { /* your OperationRequestGenerated struct fields */ },
///     did_suffix: "your_did_suffix".to_string(),
///     update_key: JsonWebKey { /* your JsonWebKey struct fields */ },
///     recovery_key: JsonWebKey { /* your JsonWebKey struct fields */ },
/// };
/// ```
///
/// # Fields
/// * `operation_request`: The generated `OperationRequestGenerated` containing the Sidetree
///   operation request data.
/// * `did_suffix`: The unique identifier (suffix) of the created DID.
/// * `update_key`: A `JsonWebKey` representing the public/private key pair used for updating
///   the DID document.
/// * `recovery_key`: A `JsonWebKey` representing the public/private key pair used for recovering
///   the DID document in case of loss or compromise.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDCreateResult {
    pub operation_request: OperationRequestGenerated,
    pub did_suffix: String,
    pub update_key: JsonWebKey,
    pub recovery_key: JsonWebKey,
}

/// `SignedDataPayload` represents the signed data payload used in Sidetree operation requests.
/// This struct stores the data needed to verify the authenticity and integrity of the operation
/// request, such as the update key and the delta hash.
///
/// # Examples
///
/// ```
/// use vade-sidetree::SignedDataPayload;
/// use vade-sidetree::JsonWebKey;
///
/// let signed_data_payload = SignedDataPayload {
///     update_key: JsonWebKey { /* your JsonWebKey struct fields */ },
///     delta_hash: "your_delta_hash".to_string(),
/// };
/// ```
///
/// # Fields
/// * `update_key`: A `JsonWebKey` representing the public/private key pair used for updating
///   the DID document. This key is included in the signed data payload to ensure that the
///   operation request is authentic.
/// * `delta_hash`: A string representing the hash of the delta object, which contains the
///   patches to update the DID document. The delta hash is used to verify the integrity of
///   the operation request.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedDataPayload {
    pub update_key: JsonWebKey,
    pub delta_hash: String,
}

/// `SideTreeConfig` represents the configuration for a Vade Sidetree system. This struct stores
/// the data needed to configure and interact with the Sidetree REST API, as well as any SDK-related
/// features.
///
/// # Examples
///
/// ```
/// use vade-sidetree::SideTreeConfig;
/// use vade-sidetree::ResolveHttpRequest;
///
/// let sidetree_config = SideTreeConfig {
///     #[cfg(feature = "sdk")]
///     request_id: std::ptr::null(),
///     #[cfg(feature = "sdk")]
///     resolve_http_request: ResolveHttpRequest { /* your ResolveHttpRequest struct fields */ },
///     sidetree_rest_api_url: "https://your-sidetree-api-url".to_string(),
/// };
/// ```
///
/// # Fields
/// * `request_id`: (SDK feature) A raw pointer to a C-style void type, representing the request
///   ID for SDK-related operations.
/// * `resolve_http_request`: (SDK feature) A `ResolveHttpRequest` struct, representing the HTTP
///   request data needed for resolving DID operations.
/// * `sidetree_rest_api_url`: The URL of the Sidetree REST API, used to interact with the
///   Sidetree system.
pub struct SideTreeConfig {
    #[cfg(feature = "sdk")]
    pub request_id: *const c_void,
    #[cfg(feature = "sdk")]
    pub resolve_http_request: ResolveHttpRequest,
    pub sidetree_rest_api_url: String,
}

/// `SidetreeDidDocument` represents a Sidetree DID Document along with its associated metadata.
/// This struct stores the data needed to describe the structure and metadata of a Sidetree
/// Decentralized Identifier (DID) Document.
///
/// # Examples
///
/// ```
/// use vade-sidetree::SidetreeDidDocument;
/// use vade-sidetree::DidDocument;
/// use vade-sidetree::DidDocumentMetadata;
///
/// let sidetree_did_document = SidetreeDidDocument {
///     context: "https://www.w3.org/ns/did/v1".to_string(),
///     did_document: DidDocument { /* your DidDocument struct fields */ },
///     did_document_metadata: DidDocumentMetadata { /* your DidDocumentMetadata struct fields */ },
/// };
/// ```
///
/// # Fields
/// * `context`: A string representing the JSON-LD context for the DID Document, used to provide
///   a semantic meaning to the document structure. Typically, this is set to
///   "https://www.w3.org/ns/did/v1".
/// * `did_document`: A `DidDocument` struct that holds the actual content of the DID Document,
///   including identifiers, keys, and service endpoints.
/// * `did_document_metadata`: A `DidDocumentMetadata` struct that contains metadata related to
///   the DID Document, such as version information or creation/update timestamps.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SidetreeDidDocument {
    #[serde(rename = "@context")]
    pub context: String,
    pub did_document: DidDocument,
    pub did_document_metadata: DidDocumentMetadata,
}


/// `DidDocument` represents the core content of a Decentralized Identifier (DID) Document.
/// This struct stores the data needed to describe the structure of a DID Document, including
/// identifiers, keys, service endpoints, and any extra fields.
///
/// # Examples
///
/// ```
/// use vade-sidetree::DidDocument;
/// use vade-sidetree::KeyAgreement;
/// use vade-sidetree::Service;
/// use serde_json::Value;
/// use std::collections::HashMap;
///
/// let did_document = DidDocument {
///     id: "did:example:123".to_string(),
///     context: Value::String("https://www.w3.org/ns/did/v1".to_string()),
///     verification_method: Some(vec![KeyAgreement { /* your KeyAgreement struct fields */ }]),
///     service: Some(vec![Service { /* your Service struct fields */ }]),
///     extra: HashMap::new(),
/// };
/// ```
///
/// # Fields
/// * `id`: A string representing the unique identifier (DID) of the DID Document.
/// * `context`: A JSON-LD `Value` representing the context for the DID Document, used to provide
///   a semantic meaning to the document structure. Typically, this is set to
///   "https://www.w3.org/ns/did/v1".
/// * `verification_method`: An optional vector of `KeyAgreement` structs, representing the
///   verification methods (e.g., public keys) associated with the DID.
/// * `service`: An optional vector of `Service` structs, representing the service endpoints
///   associated with the DID.
/// * `extra`: A `HashMap` containing any additional fields that may be present in the DID Document
///   but are not part of the standard fields.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "@context")]
    pub context: Value,
    pub verification_method: Option<Vec<KeyAgreement>>,
    pub service: Option<Vec<Service>>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// `KeyAgreement` represents a key agreement entry in a Decentralized Identifier (DID) Document.
/// This struct stores the data needed to describe the structure of a key agreement method,
/// including identifiers, controller, type, and the public key.
///
/// # Examples
///
/// ```
/// use vade-sidetree::KeyAgreement;
/// use vade-sidetree::JsonWebKeyPublic;
///
/// let key_agreement = KeyAgreement {
///     id: "did:example:123#key-1".to_string(),
///     controller: "did:example:123".to_string(),
///     type_field: "JsonWebKey2020".to_string(),
///     public_key_jwk: JsonWebKeyPublic { /* your JsonWebKeyPublic struct fields */ },
/// };
/// ```
///
/// # Fields
/// * `id`: A string representing the unique identifier of the key agreement entry within the DID Document.
/// * `controller`: A string representing the DID that controls the key agreement entry.
/// * `type_field`: A string representing the type of the key agreement method, e.g., "JsonWebKey2020".
/// * `public_key_jwk`: A `JsonWebKeyPublic` struct that holds the public key data in JWK format.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAgreement {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub public_key_jwk: JsonWebKeyPublic,
}

/// `DidDocumentMetadata` represents the metadata associated with a Decentralized Identifier (DID)
/// Document. This struct stores the data needed to describe metadata such as method-specific
/// information and the deactivated status of the DID.
///
/// # Examples
///
/// ```
/// use vade-sidetree::DidDocumentMetadata;
/// use vade-sidetree::MethodMetadata;
///
/// let did_document_metadata = DidDocumentMetadata {
///     method: MethodMetadata { /* your MethodMetadata struct fields */ },
///     deactivated: Some(false),
/// };
/// ```
///
/// # Fields
/// * `method`: A `MethodMetadata` struct that holds method-specific metadata for the DID Document.
/// * `deactivated`: An optional boolean value indicating whether the DID has been deactivated.
///   If `Some(true)`, the DID is deactivated; if `Some(false)` or `None`, the DID is active.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentMetadata {
    pub method: MethodMetadata,
    pub deactivated: Option<bool>,
}

/// `MethodMetadata` represents the method-specific metadata associated with a Decentralized
/// Identifier (DID) Document. This struct stores the data needed to describe metadata such as
/// publication status, recovery commitment, and update commitment.
///
/// # Examples
///
/// ```
/// use vade-sidetree::MethodMetadata;
///
/// let method_metadata = MethodMetadata {
///     published: true,
///     recovery_commitment: Some("your_recovery_commitment".to_string()),
///     update_commitment: Some("your_update_commitment".to_string()),
/// };
/// ```
///
/// # Fields
/// * `published`: A boolean value indicating whether the DID Document has been published to the
///   Sidetree network.
/// * `recovery_commitment`: An optional string representing the recovery commitment, a hash
///   derived from the recovery private key. This value is used to prove ownership of the recovery
///   key during a recovery operation.
/// * `update_commitment`: An optional string representing the update commitment, a hash derived
///   from the update private key. This value is used to prove ownership of the update key during
///   an update operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodMetadata {
    pub published: bool,
    pub recovery_commitment: Option<String>,
    pub update_commitment: Option<String>,
}

/// `DidUpdatePayload` represents the payload for a Decentralized Identifier (DID) update
/// operation. This struct stores the data needed to describe the update operation, including the
/// update type, keys, and patches.
///
/// # Examples
///
/// ```
/// use vade-sidetree::DidUpdatePayload;
/// use vade-sidetree::UpdateType;
/// use vade-sidetree::JsonWebKey;
/// use vade-sidetree::JsonWebKeyPublic;
/// use vade-sidetree::Patch;
///
/// let did_update_payload = DidUpdatePayload {
///     update_type: UpdateType::SomeUpdateTypeVariant,
///     update_key: Some(JsonWebKey { /* your JsonWebKey struct fields */ }),
///     recovery_key: Some(JsonWebKey { /* your JsonWebKey struct fields */ }),
///     next_update_key: Some(JsonWebKeyPublic { /* your JsonWebKeyPublic struct fields */ }),
///     next_recovery_key: Some(JsonWebKeyPublic { /* your JsonWebKeyPublic struct fields */ }),
///     patches: Some(vec![Patch { /* your Patch struct fields */ }]),
/// };
/// ```
///
/// # Fields
/// * `update_type`: An `UpdateType` enum variant representing the type of update operation to be
///   performed.
/// * `update_key`: An optional `JsonWebKey` struct representing the current update key.
/// * `recovery_key`: An optional `JsonWebKey` struct representing the current recovery key.
/// * `next_update_key`: An optional `JsonWebKeyPublic` struct representing the next update key to
///   be used for future update operations.
/// * `next_recovery_key`: An optional `JsonWebKeyPublic` struct representing the next recovery
///   key to be used for future recovery operations.
/// * `patches`: An optional vector of `Patch` structs representing the patches to be applied to
///   the DID Document as part of the update operation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DidUpdatePayload {
    pub update_type: UpdateType,
    pub update_key: Option<JsonWebKey>,
    pub recovery_key: Option<JsonWebKey>,
    pub next_update_key: Option<JsonWebKeyPublic>,
    pub next_recovery_key: Option<JsonWebKeyPublic>,
    pub patches: Option<Vec<Patch>>,
}

/// `DidCreateResponse` represents the response returned after a successful Decentralized
/// Identifier (DID) creation operation. This struct stores the data needed to describe the
/// response, including the update and recovery keys, and the created DID Document.
///
/// # Examples
///
/// ```
/// use vade-sidetree::DidCreateResponse;
/// use vade-sidetree::JsonWebKey;
/// use vade-sidetree::SidetreeDidDocument;
///
/// let did_create_response = DidCreateResponse {
///     update_key: JsonWebKey { /* your JsonWebKey struct fields */ },
///     recovery_key: JsonWebKey { /* your JsonWebKey struct fields */ },
///     did: SidetreeDidDocument { /* your SidetreeDidDocument struct fields */ },
/// };
/// ```
///
/// # Fields
/// * `update_key`: A `JsonWebKey` struct representing the update key for the created DID.
/// * `recovery_key`: A `JsonWebKey` struct representing the recovery key for the created DID.
/// * `did`: A `SidetreeDidDocument` struct representing the created DID Document.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DidCreateResponse {
    pub update_key: JsonWebKey,
    pub recovery_key: JsonWebKey,
    pub did: SidetreeDidDocument,
}

/// `TypeOptions` represents a message passed to vade containing the desired DID implementation.
/// The action will not be performed if the `type` field does not indicate a valid DID type.
///
/// # Examples
///
/// ```
/// use vade-sidetree::TypeOptions;
///
/// let type_options = TypeOptions {
///     r#type: Some("your_did_type".to_string()),
/// };
/// ```
///
/// # Fields
/// * `r#type`: An optional string representing the desired DID type for the operation. If it does
///   not match a valid DID type, the action will not be performed.
#[derive(Serialize, Deserialize)]
pub struct TypeOptions {
    pub r#type: Option<String>,
}
