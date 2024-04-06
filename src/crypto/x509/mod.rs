use crate::crypto::rsa;
use crate::idp::CertificateParams;

#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use self::openssl::*;

#[cfg(feature = "rustcrypto")]
mod rustcrypto;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto::*;

pub trait CertificateLike<Key: rsa::PrivateKeyLike>
    where
        Self: Sized,
{
    fn new(
        private_key: &Key,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn std::error::Error>>;

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;

    fn public_key(&self) -> &[u8];

    fn from_pem(pem:  &[u8]) -> Result<Self, Box<dyn std::error::Error>>;

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}