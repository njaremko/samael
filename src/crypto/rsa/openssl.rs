use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;

use crate::crypto::rsa::{PrivateKeyLike, PublicKeyLike};

pub type PrivateKey = Rsa<Private>;
pub type PublicKey = Rsa<Public>;

impl PrivateKeyLike for PrivateKey {
    fn new(bit_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::generate(bit_size as u32)?)
    }

    fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::private_key_from_pem(pem.as_bytes())?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::private_key_from_der(der)?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.private_key_to_der()?)
    }

    fn sign_sha256(&self, content_to_sign: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pkey = PKey::from_rsa(self.clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), pkey.as_ref())?;
        signer.update(content_to_sign.as_bytes())?;
        Ok(signer.sign_to_vec()?)
    }
}

impl PublicKeyLike for PublicKey {
    fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::public_key_from_pem(pem)?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::public_key_from_der(der)?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.public_key_to_der()?)
    }

    fn verify_sha256(
        &self,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let pkey = PKey::from_rsa(self.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(data)?;
        Ok(verifier.verify(signature)?)
    }
}