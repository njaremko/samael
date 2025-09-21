//! This module provides the behaviour if no crypto is available.

use openssl::pkey::{PKey, Private};
use crate::crypto::{CryptoError, CryptoProvider};
use crate::schema::CipherValue;

pub struct NoCrypto;

impl CryptoProvider for NoCrypto {
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(xml: Bytes, x509_cert_der: &[u8], id_attribute: Option<&str>) -> Result<(), CryptoError> {
       // Should have a warning??
        Ok(())
    }

    fn decrypt_assertion_key_info(cipher_value: &CipherValue, method: &str, decryption_key: &PKey<Private>) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }

    fn decrypt_assertion_value_info(cipher_value: &CipherValue, method: &str, decryption_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoDisabled)   
    }

    fn sign_xml<Bytes: AsRef<[u8]>>(xml: Bytes, private_key_der: &[u8]) -> Result<String, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }
}