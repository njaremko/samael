use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};

use rsa::{Pkcs1v15Sign};
use sha2::{Digest, Sha256};

use super::{PrivateKeyLike, PublicKeyLike};

pub use rsa::RsaPrivateKey as PrivateKey;
pub use rsa::RsaPublicKey as PublicKey;
use rsa::signature::Signer;

impl PrivateKeyLike for PrivateKey {
    fn new(bit_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();

        Ok(PrivateKey::new(&mut rng, bit_size)?)
    }

    fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_pkcs8_pem(pem).or_else(|_| Self::from_pkcs1_pem(pem))?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_pkcs8_der(der).or_else(|_| Self::from_pkcs1_der(der))?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.to_pkcs8_der()?.as_ref().to_vec())
    }

    fn sign_sha256(&self, content_to_sign: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let digest = Sha256::digest(content_to_sign.as_bytes());
        let scheme = Pkcs1v15Sign::new::<Sha256>();
        let signature = self.sign(scheme,&digest[..])?;
        Ok(signature)
    }
}

impl PublicKeyLike for PublicKey {
    fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_public_key_pem(std::str::from_utf8(pem)?)
            .or_else(|_| Self::from_pkcs1_der(pem))?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_public_key_der(der).or_else(|_| Self::from_pkcs1_der(der))?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.to_public_key_der()?.as_ref().to_vec())
    }

    fn verify_sha256(
        &self,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        //let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
        let scheme = Pkcs1v15Sign::new::<Sha256>();
        self.verify(scheme, data, signature)?;

        Ok(true)
    }
}