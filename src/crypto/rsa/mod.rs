#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use self::openssl::*;

#[cfg(feature = "rustcrypto")]
mod rustcrypto;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::*;

pub trait PrivateKeyLike
where
    Self: Sized,
{
    fn new(bit_size: usize) -> Result<Self, Box<dyn std::error::Error>>;

    fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>>;

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn sign_sha256(&self, content_to_sign: String) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

pub trait PublicKeyLike
where
    Self: Sized,
{
    fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn verify_sha256(
        &self,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>>;
}
