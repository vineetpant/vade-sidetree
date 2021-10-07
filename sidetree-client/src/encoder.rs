use base64::{encode_config, URL_SAFE_NO_PAD};

pub fn encode<T: AsRef<[u8]>>(value: T) -> String {
    encode_config(value, URL_SAFE_NO_PAD)
}
