use crate::crypto::rsa;
use x509_cert::der::{Decode, Encode};

use super::CertificateLike;
use crate::idp::CertificateParams;
pub use x509_cert::Certificate;

// #[derive(Clone)]
// pub struct Certificate<'a>(pub x509_cert::Certificate<'a>);

impl<'a> CertificateLike<rsa::PrivateKey> for Certificate<'a> {
    fn new(
        private_key: &rsa::PrivateKey,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(Encode::to_vec(self)?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<(dyn std::error::Error)>> {
        Ok(Decode::from_der(der)?)
    }

    fn public_key(&self) -> &[u8] {
        self.tbs_certificate
            .subject_public_key_info
            .subject_public_key
    }
}
