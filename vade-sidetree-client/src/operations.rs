use crate::encoder::decode;
use crate::multihash::canonicalize_then_double_hash_then_encode;
use crate::{
    did::*, multihash::canonicalize_then_hash_then_encode, secp256k1::KeyPair, Delta, Patch,
    SuffixData,
};
use crate::{
    Error, ReplaceDocument, SignedDeactivateDataPayload, SignedRecoveryDataPayload,
    SignedUpdateDataPayload,
};
use libsecp256k1::SecretKey;
use serde::{ser::SerializeMap, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub enum Operation {
    Create(SuffixData, Delta),
    Update(String, Delta, String, String),
    Recover(String, Delta, String, String),
    Deactivate(String, String, String),
}

/// Represents the input for an operation in the Sidetree system.
///
/// This struct is used to specify the input parameters for a Sidetree operation,
/// which can include creating, updating, or deactivating a DID document.
///
/// # Fields
///
/// * `public_keys`: An optional vector of `PublicKey` instances to be included in the operation.
/// * `services`: An optional vector of `Service` instances to be included in the operation.
/// * `update_key`: An optional `JsonWebKey` representing the update key to be used for the operation.
/// * `recovery_key`: An optional `JsonWebKey` representing the recovery key to be used for the operation.
#[derive(Serialize, Debug, Clone, Default)]
pub struct OperationInput {
    pub public_keys: Option<Vec<PublicKey>>,
    pub services: Option<Vec<Service>>,
    pub update_key: Option<JsonWebKey>,
    pub recovery_key: Option<JsonWebKey>,
}

impl OperationInput {
    pub fn new() -> Self {
        OperationInput::default()
    }
    pub fn with_public_keys(mut self, public_keys: Vec<PublicKey>) -> Self {
        self.public_keys = Some(public_keys);
        self
    }

    pub fn with_services(mut self, services: Vec<Service>) -> Self {
        self.services = Some(services);
        self
    }

    pub fn with_update_key(mut self, update_key: JsonWebKey) -> Self {
        self.update_key = Some(update_key);
        self
    }

    pub fn with_recovery_key(mut self, recovery_key: JsonWebKey) -> Self {
        self.recovery_key = Some(recovery_key);
        self
    }
}

/// Represents the input for a Sidetree DID update operation.
///
/// This struct is used to specify the input parameters for updating a DID document
/// in the Sidetree system.
///
/// # Fields
///
/// * `did_suffix`: A `String` representing the unique suffix of the DID to be updated.
/// * `patches`: A vector of `Patch` instances representing the changes to be applied to the DID document.
/// * `update_key`: A `JsonWebKey` representing the update key to be used for the operation.
/// * `update_commitment`: A `String` representing the update commitment value for the operation.
#[derive(Serialize, Debug, Clone, Default)]
pub struct UpdateOperationInput {
    pub did_suffix: String,
    pub patches: Vec<Patch>,
    pub update_key: JsonWebKey,
    pub update_commitment: String,
}

impl UpdateOperationInput {
    pub fn new() -> Self {
        UpdateOperationInput::default()
    }
    pub fn with_did_suffix(mut self, did_suffix: String) -> Self {
        self.did_suffix = did_suffix;
        self
    }

    pub fn with_patches(mut self, patches: Vec<Patch>) -> Self {
        self.patches = patches;
        self
    }

    pub fn with_update_key(mut self, update_key: JsonWebKey) -> Self {
        self.update_key = update_key;
        self
    }

    pub fn with_update_commitment(mut self, update_commitment: String) -> Self {
        self.update_commitment = update_commitment;
        self
    }
}

/// Represents the input for a Sidetree DID recover operation.
///
/// This struct is used to specify the input parameters for recovering a DID document
/// in the Sidetree system.
///
/// # Fields
///
/// * `did_suffix`: A `String` representing the unique suffix of the DID to be recovered.
/// * `patches`: A vector of `Patch` instances representing the changes to be applied to the DID document.
/// * `recover_key`: A `JsonWebKey` representing the recovery key to be used for the operation.
/// * `update_commitment`: A `String` representing the update commitment value for the operation.
/// * `recovery_commitment`: A `String` representing the recovery commitment value for the operation.
#[derive(Serialize, Debug, Clone, Default)]
pub struct RecoverOperationInput {
    pub did_suffix: String,
    pub patches: Vec<Patch>,
    pub recover_key: JsonWebKey,
    pub update_commitment: String,
    pub recovery_commitment: String,
}

impl RecoverOperationInput {
    pub fn new() -> Self {
        RecoverOperationInput::default()
    }
    pub fn with_did_suffix(mut self, did_suffix: String) -> Self {
        self.did_suffix = did_suffix;
        self
    }

    pub fn with_patches(mut self, patches: Vec<Patch>) -> Self {
        self.patches = patches;
        self
    }

    pub fn with_recover_key(mut self, recover_key: JsonWebKey) -> Self {
        self.recover_key = recover_key;
        self
    }

    pub fn with_update_commitment(mut self, update_commitment: String) -> Self {
        self.update_commitment = update_commitment;
        self
    }

    pub fn with_recovery_commitment(mut self, recovery_commitment: String) -> Self {
        self.recovery_commitment = recovery_commitment;
        self
    }
}

/// Represents the input for a Sidetree DID deactivate operation.
///
/// This struct is used to specify the input parameters for deactivating a DID document
/// in the Sidetree system.
///
/// # Fields
///
/// * `did_suffix`: A `String` representing the unique suffix of the DID to be deactivated.
/// * `recover_key`: A `JsonWebKey` representing the recovery key to be used for the operation.
#[derive(Serialize, Debug, Clone, Default)]
pub struct DeactivateOperationInput {
    pub did_suffix: String,
    pub recover_key: JsonWebKey,
}

impl DeactivateOperationInput {
    pub fn new() -> Self {
        DeactivateOperationInput::default()
    }
    pub fn with_did_suffix(mut self, did_suffix: String) -> Self {
        self.did_suffix = did_suffix;
        self
    }

    pub fn with_recover_key(mut self, recover_key: JsonWebKey) -> Self {
        self.recover_key = recover_key;
        self
    }
}

/// Represents the output for a Sidetree DID operation.
///
/// This struct is used to return the output parameters after performing a DID operation
/// (e.g., create, update, recover) in the Sidetree system.
///
/// # Fields
///
/// * `operation_request`: An `Operation` representing the Sidetree operation request.
/// * `did_suffix`: A `String` representing the unique suffix of the DID affected by the operation.
/// * `update_key`: A `JsonWebKey` representing the update key for the DID document.
/// * `recovery_key`: A `JsonWebKey` representing the recovery key for the DID document.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OperationOutput {
    pub operation_request: Operation,
    pub did_suffix: String,
    pub update_key: JsonWebKey,
    pub recovery_key: JsonWebKey,
}

/// Represents the output for a Sidetree DID update operation.
///
/// This struct is used to return the output parameters after performing an update operation
/// on a DID document in the Sidetree system.
///
/// # Fields
///
/// * `operation_request`: An `Operation` representing the Sidetree update operation request.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOperationOutput {
    pub operation_request: Operation,
}

impl Serialize for Operation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        match self {
            Operation::Create(suffix_data, delta) => {
                map.serialize_entry("type", "create")?;
                map.serialize_entry("suffixData", suffix_data)?;
                map.serialize_entry("delta", delta)?;
            }
            Operation::Update(did_suffix, delta, signed_data, reveal_value) => {
                map.serialize_entry("type", "update")?;
                map.serialize_entry("didSuffix", did_suffix)?;
                map.serialize_entry("delta", delta)?;
                map.serialize_entry("signedData", signed_data)?;
                map.serialize_entry("revealValue", reveal_value)?;
            }
            Operation::Recover(did_suffix, delta, signed_data, reveal_value) => {
                map.serialize_entry("type", "recover")?;
                map.serialize_entry("didSuffix", did_suffix)?;
                map.serialize_entry("delta", delta)?;
                map.serialize_entry("signedData", signed_data)?;
                map.serialize_entry("revealValue", reveal_value)?;
            }
            Operation::Deactivate(did_suffix, signed_data, reveal_value) => {
                map.serialize_entry("type", "deactivate")?;
                map.serialize_entry("didSuffix", did_suffix)?;
                map.serialize_entry("signedData", signed_data)?;
                map.serialize_entry("revealValue", reveal_value)?;
            }
        }

        map.end()
    }
}

/// Creates a Sidetree DID create operation with an optional `OperationInput`.
///
/// If no `OperationInput` is provided, a default input will be used. The function returns an
/// `OperationOutput` containing the result of the create operation.
///
/// # Arguments
///
/// * `config` - An `Option<OperationInput>` that may contain an `OperationInput` instance
///   with the desired configuration for the create operation.
///
/// # Returns
///
/// A `Result<OperationOutput, Error>` containing an `OperationOutput` instance with
/// the output of the create operation, or an `Error` if the operation fails.
pub fn create<'a>(config: Option<OperationInput>) -> Result<OperationOutput, Error<'a>> {
    create_config(config.unwrap_or_else(|| OperationInput::new()))
}

/// Creates a Sidetree DID create operation using the provided `OperationInput` configuration.
///
/// This function returns an `OperationOutput` containing the result of the create operation.
///
/// # Arguments
///
/// * `config` - An `OperationInput` instance with the desired configuration for the create operation.
///
/// # Returns
///
/// A `Result<OperationOutput, Error>` containing an `OperationOutput` instance with
/// the output of the create operation, or an `Error` if the operation fails.
pub fn create_config<'a>(config: OperationInput) -> Result<OperationOutput, Error<'a>> {
    let document = Document {
        public_keys: config.public_keys,
        services: config.services,
    };
    let patches = vec![Patch::Replace(ReplaceDocument { document })];

    let update_key = config
        .update_key
        .unwrap_or_else(|| (&KeyPair::random()).into());
    let mut update_key_public = update_key.clone();
    update_key_public.d = None;

    let delta = Delta {
        update_commitment: canonicalize_then_double_hash_then_encode(&update_key_public).unwrap(),
        patches,
    };

    let delta_hash =
        canonicalize_then_hash_then_encode(&delta, crate::multihash::HashAlgorithm::Sha256);

    let recovery_key = config
        .recovery_key
        .unwrap_or_else(|| (&KeyPair::random()).into());
    let mut recovery_key_public = recovery_key.clone();
    recovery_key_public.d = None;

    let suffix_data = SuffixData {
        delta_hash,
        recovery_commitment: canonicalize_then_double_hash_then_encode(&recovery_key_public)
            .unwrap(),
    };

    let did_suffix = compute_unique_suffix(&suffix_data);
    let operation = Operation::Create(suffix_data, delta);

    Ok(OperationOutput {
        update_key,
        recovery_key,
        operation_request: operation,
        did_suffix,
    })
}

/// Creates a Sidetree DID update operation using the provided `UpdateOperationInput` configuration.
///
/// This function returns an `UpdateOperationOutput` containing the result of the update operation.
///
/// # Arguments
///
/// * `config` - An `UpdateOperationInput` instance with the desired configuration for the update operation.
///
/// # Returns
///
/// A `Result<UpdateOperationOutput, Error>` containing an `UpdateOperationOutput` instance with
/// the output of the update operation, or an `Error` if the operation fails.
pub fn update<'a>(config: UpdateOperationInput) -> Result<UpdateOperationOutput, Error<'a>> {
    let mut public_key_x = decode(config.update_key.x).unwrap();
    let mut public_key_y = decode(config.update_key.y.unwrap()).unwrap();
    let mut full_pub_key = Vec::<u8>::new();
    full_pub_key.append(&mut vec![0x04]);
    full_pub_key.append(&mut public_key_x);
    full_pub_key.append(&mut public_key_y);
    let mut public_key_arr: [u8; 65] = [0; 65];
    public_key_arr.copy_from_slice(&full_pub_key[0..65]);
    let mut secret_key = None;
    if let Some(d) = config.update_key.d {
        let secret_key_decoded = decode(d).unwrap();
        let mut secret_key_arr: [u8; 32] = Default::default();
        secret_key_arr.copy_from_slice(&secret_key_decoded[0..32]);
        secret_key = Some(SecretKey::parse(&secret_key_arr).unwrap());
    }
    let public_key = libsecp256k1::PublicKey::parse(&public_key_arr).unwrap();

    let update_keypair = KeyPair {
        public_key,
        secret_key,
    };

    let mut update_key_public: JsonWebKey = (&update_keypair).into();
    update_key_public.d = None;
    update_key_public.nonce = config.update_key.nonce;

    let delta = Delta {
        update_commitment: config.update_commitment,
        patches: config.patches,
    };

    let delta_hash =
        canonicalize_then_hash_then_encode(&delta, crate::multihash::HashAlgorithm::Sha256);

    let signed_data_payload = SignedUpdateDataPayload {
        update_key: update_key_public.clone(),
        delta_hash,
    };

    let protected_header = "{\"alg\":\"ES256K\"}";
    let mut message = String::new();
    message.push_str(&base64::encode_config(
        protected_header,
        base64::URL_SAFE_NO_PAD,
    ));
    message.push_str(".");
    message.push_str(&base64::encode_config(
        serde_json::to_string(&signed_data_payload).unwrap(),
        base64::URL_SAFE_NO_PAD,
    ));

    let mut hasher = Sha256::new();
    // write input message
    hasher.update(message.clone());

    // read hash digest and consume hasher
    let message_hash = hasher.finalize();

    let (signed_data, _) = update_keypair.sign(message_hash.as_slice());

    message.push_str(".");
    base64::encode_config_buf(
        signed_data.serialize(),
        base64::URL_SAFE_NO_PAD,
        &mut message,
    );

    let reveal_value = canonicalize_then_hash_then_encode(
        &update_key_public.clone(),
        crate::multihash::HashAlgorithm::Sha256,
    );

    let operation = Operation::Update(config.did_suffix, delta, message, reveal_value);

    Ok(UpdateOperationOutput {
        operation_request: operation,
    })
}

/// Creates a Sidetree DID recover operation using the provided `RecoverOperationInput` configuration.
///
/// This function returns an `UpdateOperationOutput` containing the result of the recover operation.
///
/// # Arguments
///
/// * `config` - A `RecoverOperationInput` instance with the desired configuration for the recover operation.
///
/// # Returns
///
/// A `Result<UpdateOperationOutput, Error>` containing an `UpdateOperationOutput` instance with
/// the output of the recover operation, or an `Error` if the operation fails.
pub fn recover<'a>(config: RecoverOperationInput) -> Result<UpdateOperationOutput, Error<'a>> {
    let mut public_key_x = decode(config.recover_key.x).unwrap();
    let mut public_key_y = decode(config.recover_key.y.unwrap()).unwrap();
    let mut full_pub_key = Vec::<u8>::new();
    full_pub_key.append(&mut vec![0x04]);
    full_pub_key.append(&mut public_key_x);
    full_pub_key.append(&mut public_key_y);
    let mut public_key_arr: [u8; 65] = [0; 65];
    public_key_arr.copy_from_slice(&full_pub_key[0..65]);
    let mut secret_key = None;
    if let Some(d) = config.recover_key.d {
        let secret_key_decoded = decode(d).unwrap();
        let mut secret_key_arr: [u8; 32] = Default::default();
        secret_key_arr.copy_from_slice(&secret_key_decoded[0..32]);
        secret_key = Some(SecretKey::parse(&secret_key_arr).unwrap());
    }
    let public_key = libsecp256k1::PublicKey::parse(&public_key_arr).unwrap();

    let recovery_keypair = KeyPair {
        public_key,
        secret_key,
    };

    let mut recovery_key_public: JsonWebKeyPublic = (&recovery_keypair).into();
    recovery_key_public.nonce = config.recover_key.nonce;

    let delta = Delta {
        update_commitment: config.update_commitment,
        patches: config.patches,
    };

    let delta_hash =
        canonicalize_then_hash_then_encode(&delta, crate::multihash::HashAlgorithm::Sha256);

    let signed_data_payload = SignedRecoveryDataPayload {
        delta_hash,
        recovery_key: recovery_key_public.clone(),
        recovery_commitment: config.recovery_commitment,
    };

    let protected_header = "{\"alg\":\"ES256K\"}";
    let mut message = String::new();
    message.push_str(&base64::encode_config(
        protected_header,
        base64::URL_SAFE_NO_PAD,
    ));
    message.push_str(".");
    message.push_str(&base64::encode_config(
        serde_json::to_string(&signed_data_payload).unwrap(),
        base64::URL_SAFE_NO_PAD,
    ));

    let mut hasher = Sha256::new();
    // write input message
    hasher.update(message.clone());

    // read hash digest and consume hasher
    let message_hash = hasher.finalize();

    let (signed_data, _) = recovery_keypair.sign(message_hash.as_slice());

    message.push_str(".");
    base64::encode_config_buf(
        signed_data.serialize(),
        base64::URL_SAFE_NO_PAD,
        &mut message,
    );

    let reveal_value = canonicalize_then_hash_then_encode(
        &recovery_key_public.clone(),
        crate::multihash::HashAlgorithm::Sha256,
    );

    let operation = Operation::Recover(config.did_suffix, delta, message, reveal_value);

    Ok(UpdateOperationOutput {
        operation_request: operation,
    })
}

/// Creates a Sidetree DID deactivate operation using the provided `DeactivateOperationInput` configuration.
///
/// This function returns an `UpdateOperationOutput` containing the result of the deactivate operation.
///
/// # Arguments
///
/// * `config` - A `DeactivateOperationInput` instance with the desired configuration for the deactivate operation.
///
/// # Returns
///
/// A `Result<UpdateOperationOutput, Error>` containing an `UpdateOperationOutput` instance with
/// the output of the deactivate operation, or an `Error` if the operation fails.
pub fn deactivate<'a>(
    config: DeactivateOperationInput,
) -> Result<UpdateOperationOutput, Error<'a>> {
    let mut public_key_x = decode(config.recover_key.x).unwrap();
    let mut public_key_y = decode(config.recover_key.y.unwrap()).unwrap();
    let mut full_pub_key = Vec::<u8>::new();
    full_pub_key.append(&mut vec![0x04]);
    full_pub_key.append(&mut public_key_x);
    full_pub_key.append(&mut public_key_y);
    let mut public_key_arr: [u8; 65] = [0; 65];
    public_key_arr.copy_from_slice(&full_pub_key[0..65]);
    let mut secret_key = None;
    if let Some(d) = config.recover_key.d {
        let secret_key_decoded = decode(d).unwrap();
        let mut secret_key_arr: [u8; 32] = Default::default();
        secret_key_arr.copy_from_slice(&secret_key_decoded[0..32]);
        secret_key = Some(SecretKey::parse(&secret_key_arr).unwrap());
    }
    let public_key = libsecp256k1::PublicKey::parse(&public_key_arr).unwrap();

    let recovery_keypair = KeyPair {
        public_key,
        secret_key,
    };

    let mut recovery_key_public: JsonWebKeyPublic = (&recovery_keypair).into();
    recovery_key_public.nonce = config.recover_key.nonce;
    let signed_data_payload = SignedDeactivateDataPayload {
        recovery_key: recovery_key_public.clone(),
        did_suffix: config.did_suffix.clone(),
    };

    let protected_header = "{\"alg\":\"ES256K\"}";
    let mut message = String::new();
    message.push_str(&base64::encode_config(
        protected_header,
        base64::URL_SAFE_NO_PAD,
    ));
    message.push_str(".");
    message.push_str(&base64::encode_config(
        serde_json::to_string(&signed_data_payload).unwrap(),
        base64::URL_SAFE_NO_PAD,
    ));

    let mut hasher = Sha256::new();
    // write input message
    hasher.update(message.clone());

    // read hash digest and consume hasher
    let message_hash = hasher.finalize();

    let (signed_data, _) = recovery_keypair.sign(message_hash.as_slice());

    message.push_str(".");
    base64::encode_config_buf(
        signed_data.serialize(),
        base64::URL_SAFE_NO_PAD,
        &mut message,
    );

    let reveal_value = canonicalize_then_hash_then_encode(
        &recovery_key_public.clone(),
        crate::multihash::HashAlgorithm::Sha256,
    );
    let operation = Operation::Deactivate(config.did_suffix, message, reveal_value);

    Ok(UpdateOperationOutput {
        operation_request: operation,
    })
}

#[cfg(test)]
mod test {
    use crate::did::{JsonWebKey, PublicKey, Purpose};

    use super::{create, create_config, Operation, OperationInput};

    #[test]
    fn generate_create_operation() {
        let result = create(None).unwrap();
        let json = serde_json::to_string_pretty(&result.operation_request);

        assert!(matches!(json, Result::Ok(_)));
        assert!(matches!(result.operation_request, Operation::Create(_, _)));
        assert!(result.did_suffix.len() > 0);

        println!("did:ion:{}", result.did_suffix);
        println!("{}", json.unwrap());
    }

    #[test]
    fn generate_create_operation_with_input() {
        let public_key = PublicKey {
            controller: None,
            id: "key-1".into(),
            purposes: Some(vec![Purpose::Authentication, Purpose::CapabilityDelegation]),
            key_type: "SampleVerificationKey2020".into(),
            public_key_jwk: None,
        };

        let config = OperationInput::new().with_public_keys(vec![public_key]);

        let result = create_config(config).unwrap();

        assert!(matches!(result.operation_request, Operation::Create(_, _)));
        assert!(result.did_suffix.len() > 0);
    }

    #[test]
    fn create_configurable_input() {
        let input = OperationInput::default()
            .with_public_keys(vec![])
            .with_update_key(JsonWebKey::default());

        assert!(matches!(input.update_key, Some(_)));
        assert!(matches!(input.public_keys, Some(_)));
        assert!(input.public_keys.unwrap().is_empty());
    }
}
