use base64::{decode_config, encode_config, DecodeError, URL_SAFE_NO_PAD};

/// Encodes a value as a URL-safe base64 string with no padding.
///
/// This function takes a value that implements `AsRef<[u8]>` and returns its
/// URL-safe base64 representation without padding.
///
/// # Arguments
///
/// * `value`: A value implementing `AsRef<[u8]>` that you want to encode.
///
/// # Returns
///
/// A `String` representing the URL-safe base64 encoding without padding of the input value.
///
/// # Examples
///
/// ```
/// use your_crate_name::{encode, decode};
///
/// let input = b"hello";
/// let encoded = encode(input);
/// assert_eq!(encoded, "aGVsbG8");
/// ```
pub fn encode<T: AsRef<[u8]>>(value: T) -> String {
    encode_config(value, URL_SAFE_NO_PAD)
}

/// Decodes a URL-safe base64 string with no padding into a byte vector.
///
/// This function takes a value that implements `AsRef<[u8]>` representing a
/// URL-safe base64 encoded string without padding and returns the decoded bytes
/// as a `Vec<u8>`.
///
/// # Arguments
///
/// * `value`: A value implementing `AsRef<[u8]>` that you want to decode.
///
/// # Returns
///
/// A `Result<Vec<u8>, DecodeError>` where the `Ok` variant contains the decoded
/// bytes as a `Vec<u8>`, and the `Err` variant contains a `DecodeError`.
///
/// # Examples
///
/// ```
/// use your_crate_name::{encode, decode};
///
/// let encoded = "aGVsbG8";
/// let decoded = decode(encoded).unwrap();
/// assert_eq!(decoded, b"hello");
/// ```
pub fn decode<T: AsRef<[u8]>>(value: T) -> Result<Vec<u8>, DecodeError> {
    decode_config(&value, URL_SAFE_NO_PAD)
}
