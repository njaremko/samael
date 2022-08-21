use crate::crypto::rsa;
use x509_cert::der::{Decode, Encode};
pub use x509_cert::{
    der::{
        asn1::{BitStringRef, UIntRef},
        Sequence,
    },
    name::{Name, RdnSequence},
    TbsCertificate, Version,
};

use crate::idp::CertificateParams;

#[derive(Clone)]
pub struct Certificate<'a>(pub x509_cert::Certificate<'a>);

impl<'a> Certificate<'a> {
    pub fn new(
        private_key: &rsa::RsaPrivateKey,
        params: &CertificateParams,
    ) -> Result<Certificate<'static>, Box<dyn std::error::Error>> {
        todo!("Certificate creation is not yet supported for the rustcrypto backend");
        // let sn: [u8; 0] = [];
        // Certificate {
        // tbs_certificate: TbsCertificate {
        //     version: Version::V2,
        //     serial_number: UIntRef::new(&sn)?,
        //     signature: AlgorithmIdentifier,
        //     issuer: Name::encode_from_string(params.issuer_name)?.map(Name),
        //     validity: Validity,
        //     subject: Name::encode_from_string(params.common_name)?.map(Name),
        // subject_public_key_info: SubjectPublicKeyInfo<'a>,
        // issuer_unique_id: Option<BitStringRef<'a>>,
        // subject_unique_id: Option<BitStringRef<'a>>,
        // extensions: Option<crate::ext::Extensions<'a>>,
        // },
        // signature_algorithm: AlgorithmIdentifier {

        // },
        // signature: BitStringRef {

        // },
        // }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.0.to_vec()?)
    }

    pub fn from_der(bytes: &'a [u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(x509_cert::Certificate::from_der(bytes)?))
    }

    pub fn public_key(&self) -> &'a [u8] {
        self.0
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
    }
}
