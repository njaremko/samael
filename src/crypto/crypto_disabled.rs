//! This module provides the behaviour if no crypto is available.

use crate::crypto::{AllowedSignatureAlgorithm, CertificateDer, CryptoError, CryptoProvider, ReduceMode};
use crate::schema::CipherValue;

pub struct NoCrypto;

impl CryptoProvider for NoCrypto {
    type PrivateKey = ();
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        _xml: Bytes,
        _x509_cert_der: &CertificateDer,
        _id_attribute: Option<&str>,
    ) -> Result<(), CryptoError> {
        // todo: Should have a warning??
        Ok(())
    }

    fn reduce_xml_to_signed_with_allowed_algorithms(
        _xml_str: &str,
        _certs: &[CertificateDer],
        _reduce_mode: ReduceMode,
        _allowed_algorithms: Option<&[AllowedSignatureAlgorithm]>,
    ) -> Result<String, CryptoError> {
        Err(CryptoError::CryptoDisabled)
    }

    fn decrypt_assertion_key_info(
        _cipher_value: &CipherValue,
        _method: &str,
        _decryption_key: &Self::PrivateKey,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_xml_to_signed_fails_closed_when_crypto_is_disabled() {
        let error = NoCrypto::reduce_xml_to_signed("<Response/>", &[], ReduceMode::ValidateAndMark)
            .expect_err("signature reduction should fail when crypto support is disabled");

        assert!(matches!(error, CryptoError::CryptoDisabled));
    }
}
