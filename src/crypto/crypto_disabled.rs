//! This module provides the behaviour if no crypto is available.

use crate::crypto::{CryptoError, CryptoProvider};
use crate::schema::CipherValue;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

pub struct NoCrypto;

impl CryptoProvider for NoCrypto {
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        _xml: Bytes,
        _x509_cert_der: &[u8],
        _id_attribute: Option<&str>,
    ) -> Result<(), CryptoError> {
        // todo: Should have a warning??
        Ok(())
    }

    fn reduce_xml_to_signed(_xml_str: &str, _certs: &[X509]) -> Result<String, CryptoError> {
        // Since we cannot verify anything. Return empty.
        Ok(String::new())
    }

    fn decrypt_assertion_key_info(
        _cipher_value: &CipherValue,
        _method: &str,
        _decryption_key: &PKey<Private>,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }

    fn decrypt_assertion_value_info(
        _cipher_value: &CipherValue,
        _method: &str,
        _decryption_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }

    fn sign_xml<Bytes: AsRef<[u8]>>(
        _xml: Bytes,
        _private_key_der: &[u8],
    ) -> Result<String, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }
}
