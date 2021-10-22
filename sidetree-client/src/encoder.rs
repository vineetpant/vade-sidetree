use base64::{decode_config, encode_config, DecodeError, URL_SAFE_NO_PAD};

pub fn encode<T: AsRef<[u8]>>(value: T) -> String {
    encode_config(value, URL_SAFE_NO_PAD)
}

pub fn decode<T: AsRef<[u8]>>(value: T) -> Result<Vec<u8>, DecodeError> {
    decode_config(&value, URL_SAFE_NO_PAD)
}
