use std::todo;

use ::multihash::{Code, MultihashDigest};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::encoder;

/// Canonicalizes a serializable value using JCS (JSON Canonicalization Scheme).
///
/// This function takes a serializable value and returns its canonicalized JSON
/// representation as a vector of bytes. The canonicalization process follows the
/// JCS (JSON Canonicalization Scheme) standard.
///
/// # Arguments
///
/// * `value`: A reference to a value that implements `Serialize`. This is the value to be canonicalized.
///
/// # Errors
///
/// Returns an error as a `String` if the canonicalization process fails.
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|err| format!("{}", err))
}

/// Canonicalizes a serializable value, then hashes and encodes the result.
///
/// This function takes a serializable value and performs the following operations:
/// 1. Canonicalizes the value using JCS (JSON Canonicalization Scheme).
/// 2. Hashes the canonicalized JSON representation using the specified hash algorithm.
/// 3. Encodes the hash as a URL-safe, unpadded base64 string.
///
/// # Arguments
///
/// * `value`: A reference to a value that implements `Serialize`. This is the value to be canonicalized, hashed, and encoded.
/// * `algorithm`: The `HashAlgorithm` to be used for hashing the canonicalized JSON representation.
///
/// # Errors
///
/// Returns an error as a `String` if the canonicalization process fails.
pub fn canonicalize_then_hash_then_encode<T: Serialize + ?Sized>(
    value: &T,
    algorithm: HashAlgorithm,
) -> String {
    let canonicalized_string_buffer = match canonicalize(value){
        Ok(value) => value,
        Err(err) => return err,
    };

    hash_then_encode(&canonicalized_string_buffer, algorithm)
}

/// Canonicalizes a serializable value, then double-hashes and encodes the result.
///
/// This function takes a serializable value and performs the following operations:
/// 1. Canonicalizes the value using JCS (JSON Canonicalization Scheme).
/// 2. Hashes the canonicalized JSON representation using SHA-256.
/// 3. Hashes the resulting hash once more using SHA-256.
/// 4. Encodes the final hash as a multihash-encoded, URL-safe, unpadded base64 string.
///
/// # Arguments
///
/// * `value`: A reference to a value that implements `Serialize`. This is the value to be canonicalized, double-hashed, and encoded.
///
/// # Errors
///
/// Returns an error as a `String` if the canonicalization process fails.
pub fn canonicalize_then_double_hash_then_encode<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, String> {
    let content_buffer = match canonicalize(value) {
        Ok(x) => x,
        Err(_) => return Err("failed to canonicalize".to_string()),
    };

    let intermediate_hash_buffer =
        hash_as_non_multihash_buffer(content_buffer.as_slice(), HashAlgorithm::Sha256);
    let multihash_encoded_string =
        hash_then_encode(intermediate_hash_buffer.as_slice(), HashAlgorithm::Sha256);
    Ok(multihash_encoded_string)
}

/// Computes the hash of the input buffer using the specified hash algorithm.
///
/// This function takes a byte slice and a hash algorithm, and returns the hashed
/// result as a `Vec<u8>`.
///
/// # Arguments
///
/// * `buffer`: A byte slice representing the data to be hashed.
/// * `algorithm`: The hash algorithm to be used for hashing the data. This should be a variant of the `HashAlgorithm` enum.
///
/// # Supported Hash Algorithms
///
/// The following hash algorithms are currently supported:
///
/// * `HashAlgorithm::Sha256`: SHA-256
/// * `HashAlgorithm::Sha3_256`: SHA3-256
pub fn hash(buffer: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Code::Sha2_256.digest(buffer).to_bytes(),
        HashAlgorithm::Sha3_256 => Code::Sha3_256.digest(buffer).to_bytes(),
    }
}

/// Computes the hash of the input buffer using the specified hash algorithm, returning a non-multihash encoded buffer.
///
/// This function takes a byte slice and a hash algorithm, and returns the hashed
/// result as a `Vec<u8>` without multihash encoding.
///
/// # Arguments
///
/// * `buffer`: A byte slice representing the data to be hashed.
/// * `algorithm`: The hash algorithm to be used for hashing the data. This should be a variant of the `HashAlgorithm` enum.
///
/// # Supported Hash Algorithms
///
/// The following hash algorithms are currently supported:
///
/// * `HashAlgorithm::Sha256`: SHA-256
/// * `HashAlgorithm::Sha3_256`: SHA3-256 (not implemented yet)
pub fn hash_as_non_multihash_buffer(buffer: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(buffer).to_vec(),
        HashAlgorithm::Sha3_256 => todo!(),
    }
}

/// Computes the hash of the input buffer using the specified hash algorithm, and then returns the multihash encoded result as a `String`.
///
/// This function takes a byte slice and a hash algorithm, computes the hash of the input data,
/// and returns the multihash encoded result as a `String`.
///
/// # Arguments
///
/// * `buffer`: A byte slice representing the data to be hashed.
/// * `algorithm`: The hash algorithm to be used for hashing the data. This should be a variant of the `HashAlgorithm` enum.
///
/// # Supported Hash Algorithms
///
/// The following hash algorithms are currently supported:
///
/// * `HashAlgorithm::Sha256`: SHA-256
/// * `HashAlgorithm::Sha3_256`: SHA3-256
pub fn hash_then_encode(buffer: &[u8], algorithm: HashAlgorithm) -> String {
    let multihash_buffer = hash(buffer, algorithm);
    encoder::encode(multihash_buffer)
}

pub enum HashAlgorithm {
    Sha256,
    #[allow(dead_code)]
    Sha3_256,
}

#[cfg(test)]
pub mod test {
    use ::multihash::{Code, MultihashDigest};

    #[test]
    pub fn test() {
        let digest = Code::Sha2_256.digest(b"hello");

        println!("{:?}", digest);
        println!("{:?}", digest.to_bytes())
    }
}
