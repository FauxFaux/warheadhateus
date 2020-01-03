use crate::error::AWSAuthError;
use hmac::Mac as _;
use sha2::digest::Digest as _;

/// Hash the given data (or an empty string) with SHA256.
pub fn hashed_data(data: Option<&[u8]>) -> Result<String, AWSAuthError> {
    let data_to_hash = match data {
        Some(d) => d,
        None => b"",
    };
    Ok(hex::encode(sha2::Sha256::digest(data_to_hash)))
}

/// Sign the given data with the given key (HMAC-SHA256).
pub fn signed_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, AWSAuthError> {
    let mut hmac: hmac::Hmac<sha2::Sha256> =
        hmac::Hmac::new_varkey(key).map_err(|_| AWSAuthError::Other("invalid key"))?;
    hmac.input(data);
    Ok(hmac.result().code().to_vec())
}
