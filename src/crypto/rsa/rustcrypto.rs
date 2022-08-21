// use rsa::pkcs1::{TryFrom, RsaPrivateKey as FromRsaPrivateKey, RsaPublicKey as FromRsaPublicKey};
// use rsa::pkcs8::PublicKey;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};

use rsa::{Hash, PaddingScheme, PublicKey as FromPublicKey};
use sha2::{Digest, Sha256};

pub use rsa::RsaPrivateKey;
pub use rsa::RsaPublicKey;

#[derive(Clone)]
pub struct PrivateKey(pub RsaPrivateKey);

impl PrivateKey {
    pub fn new(bit_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();

        Ok(Self(RsaPrivateKey::new(&mut rng, bit_size)?))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(PrivateKey(
            RsaPrivateKey::from_pkcs8_pem(pem).or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))?,
        ))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(PrivateKey(
            RsaPrivateKey::from_pkcs8_der(der).or_else(|_| RsaPrivateKey::from_pkcs1_der(der))?,
        ))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.0.to_pkcs8_der()?.as_ref().to_vec())
    }

    pub fn sign_sha256(
        &self,
        content_to_sign: String,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
        let hashed = Sha256::digest(content_to_sign.as_bytes());
        let signature = self.0.sign(padding, &hashed[..])?;

        Ok(signature)
    }
}

#[derive(Clone)]
pub struct PublicKey(pub RsaPublicKey);

impl PublicKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(
            RsaPublicKey::from_public_key_pem(std::str::from_utf8(pem)?)
                .or_else(|_| RsaPublicKey::from_pkcs1_der(pem))?,
        ))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(
            RsaPublicKey::from_public_key_der(der)
                .or_else(|_| RsaPublicKey::from_pkcs1_der(der))?,
        ))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.0.to_public_key_der()?.as_ref().to_vec())
    }

    pub fn verify_sha256(
        &self,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));

        self.0.verify(padding, data, signature)?;

        Ok(true)
    }
}
