use crate::Error;
use crate::{
    did::*,
    multihash::{canonicalize_then_double_hash_then_encode, canonicalize_then_hash_then_encode},
    secp256k1::KeyPair,
    Delta, Patch, SuffixData,
};
use serde::{ser::SerializeMap, Serialize};

#[derive(Debug, Clone)]
pub enum Operation {
    Create(SuffixData, Delta),
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct OperationInput {
    public_keys: Option<Vec<PublicKey>>,
    services: Option<Vec<Service>>,
    update_key: Option<JsonWebKey>,
    recovery_key: Option<JsonWebKey>,
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

#[derive(Serialize, Debug, Clone)]
pub struct OperationOutput {
    operation_request: Operation,
    did_suffix: String,
    update_key: JsonWebKey,
    recovery_key: JsonWebKey,
    public_keys: Vec<PublicKey>,
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
        }

        map.end()
    }
}

pub fn create<'a>() -> Result<OperationOutput, Error<'a>> {
    let signing_key = KeyPair::random();
    let signing_key_public = signing_key.to_public_key("key-1".into(), Some(Purpose::all()));

    create_config(OperationInput::new().with_public_keys(vec![signing_key_public]))
}

pub fn create_config<'a>(config: OperationInput) -> Result<OperationOutput, Error<'a>> {
    if let None = config.public_keys {
        return Err(Error::MissingField("public_keys"));
    }

    let update_key = KeyPair::random();
    let recovery_key = KeyPair::random();

    let document = Document {
        public_keys: config.public_keys.clone().unwrap(),
        services: vec![],
    };

    let patches = vec![Patch::Replace(document)];

    let mut update_key_public: JsonWebKey = (&update_key).into();
    update_key_public.d = None;

    let delta = Delta {
        update_commitment: canonicalize_then_double_hash_then_encode(&update_key_public).unwrap(),
        patches,
    };

    let delta_hash = canonicalize_then_hash_then_encode(&delta, crate::multihash::HashAlgorithm::Sha256);

    let mut recovery_key_public: JsonWebKey = (&recovery_key).into();
    recovery_key_public.d = None;

    let suffix_data = SuffixData {
        delta_hash,
        recovery_commitment: canonicalize_then_double_hash_then_encode(&recovery_key_public).unwrap(),
        data_type: None,
    };

    let did_suffix = compute_unique_suffix(&suffix_data);
    let operation = Operation::Create(suffix_data, delta);

    Ok(OperationOutput {
        update_key: (&update_key).into(),
        recovery_key: (&recovery_key).into(),
        public_keys: config.public_keys.unwrap(),
        operation_request: operation,
        did_suffix,
    })
}

#[cfg(test)]
mod test {
    use crate::did::{JsonWebKey, PublicKey, Purpose};

    use super::{create, create_config, Operation, OperationInput};

    #[test]
    fn generate_create_operation() {
        let result = create().unwrap();
        let json = serde_json::to_string_pretty(&result.operation_request);

        assert!(matches!(json, Result::Ok(_)));
        assert!(matches!(result.operation_request, Operation::Create(_, _)));
        assert!(result.did_suffix.len() > 0);

        println!("did:ion:{}", result.did_suffix);
        println!("{}", json.unwrap());
    }

    #[test]
    fn generate_create_operation_with_input() {
        let putblic_key = PublicKey {
            id: "key-1".into(),
            purposes: Some(Purpose::AUTHENTICATION | Purpose::CAPABILITY_DELEGATION),
            key_type: "SampleVerificationKey2020".into(),
            jwk: None,
        };

        let config = OperationInput::new().with_public_keys(vec![putblic_key]);

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
