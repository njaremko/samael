use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;

type RsaPrivate = Rsa<Private>;
type RsaPublic = Rsa<Public>;

#[derive(Clone)]
pub struct PrivateKey(pub RsaPrivate);

impl PrivateKey {
    pub fn new(bit_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(RsaPrivate::generate(bit_size as u32)?))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::private_key_from_pem(pem)?)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::private_key_from_der(der)?)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.0.to_pkcs8_der()?.as_ref().to_vec())
    }

    pub fn sign_sha256(
        &self,
        content_to_sign: String,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pkey = PKey::from_rsa(self.0)?;

        let mut signer = Signer::new(MessageDigest::sha256(), pkey.as_ref())?;

        signer.update(content_to_sign.as_bytes())?;

        Ok(signer.sign_to_vec()?)
    }
}

#[derive(Clone)]
pub struct PublicKey(pub RsaPublic);

impl PublicKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::public_key_from_pem(pem)?)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Rsa::public_key_from_der(der)?)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.0.to_public_key_der()?.as_ref().to_vec())
    }

    pub fn verify_sha256(
        &self,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), self.0)?;

        verifier.update(data)?;

        Ok(verifier.verify(signature)?)
    }
}
