use secp256k1::{Message, PublicKey, RecoveryId, SecretKey, Signature};

use crate::{
    did::{JsonWebKey, JsonWebKeyPublic, Purpose},
    encoder::encode,
};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: Option<SecretKey>,
}

impl KeyPair {
    pub fn sign(&self, message: &[u8]) -> (Signature, RecoveryId) {
        secp256k1::sign(
            &Message::parse_slice(message).unwrap(),
            &self.secret_key.as_ref().unwrap(),
        )
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        secp256k1::verify(
            &Message::parse_slice(message).unwrap(),
            &Signature::parse_slice(signature).unwrap(),
            &self.public_key,
        )
    }

    pub fn to_public_key(&self, id: String, purposes: Option<Vec<Purpose>>) -> crate::PublicKey {
        let mut jwk: JsonWebKey = self.into();
        jwk.d = None;

        crate::PublicKey {
            id,
            controller: None,
            key_type: "EcdsaSecp256k1VerificationKey2019".to_string(),
            purposes,
            public_key_jwk: Some(jwk),
        }
    }

    pub fn random() -> KeyPair {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("couldn't generate random seed");

        // TODO: Add rng support
        let secret_key = SecretKey::parse(&seed).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);

        KeyPair {
            public_key,
            secret_key: Some(secret_key),
        }
    }
}

impl From<&KeyPair> for JsonWebKey {
    fn from(keypair: &KeyPair) -> Self {
        let serialized_public_key = keypair.public_key.serialize();

        JsonWebKey {
            key_type: "EC".into(),
            curve: "secp256k1".into(),
            x: encode(serialized_public_key[1..33].as_ref()),
            y: Some(encode(serialized_public_key[33..65].as_ref())),
            d: keypair
                .secret_key
                .as_ref()
                .map(|secret_key| encode(secret_key.serialize())),
            nonce: None,
        }
    }
}

impl From<&KeyPair> for JsonWebKeyPublic {
    fn from(keypair: &KeyPair) -> Self {
        let serialized_public_key = keypair.public_key.serialize();

        JsonWebKeyPublic {
            key_type: "EC".into(),
            curve: "secp256k1".into(),
            x: encode(serialized_public_key[1..33].as_ref()),
            y: Some(encode(serialized_public_key[33..65].as_ref())),
            nonce: None,
        }
    }
}

impl From<&JsonWebKey> for JsonWebKeyPublic {
    fn from(key: &JsonWebKey) -> Self {
        JsonWebKeyPublic {
            key_type: "EC".into(),
            curve: "secp256k1".into(),
            x: key.x.clone(),
            y: key.y.clone(),
            nonce: key.nonce.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn generate_random_key() {
        let keypair = super::KeyPair::random();

        assert!(matches!(keypair.secret_key, Some(_)));
    }
}
