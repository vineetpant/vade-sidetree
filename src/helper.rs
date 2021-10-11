use crate::datatypes::SignedDataPayload;
use sha2::{Digest, Sha256};
use sidetree_client::secp256k1;

pub fn createSignedJWS(
    signed_data_payload: SignedDataPayload,
    update_keypair: secp256k1::KeyPair,
) -> Result<String, Box<dyn std::error::Error>> {
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
    Ok(message)
}
