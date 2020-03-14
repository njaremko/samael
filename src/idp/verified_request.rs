use crate::crypto::{self, verify_signed_xml};
use crate::schema::AuthnRequest;

use super::error::Error;

pub struct UnverifiedAuthnRequest<'a> {
    pub request: AuthnRequest,
    xml: &'a str,
}

impl<'a> UnverifiedAuthnRequest<'a> {
    pub fn from_xml(xml: &str) -> Result<UnverifiedAuthnRequest, Error> {
        Ok(UnverifiedAuthnRequest {
            request: xml.parse()?,
            xml,
        })
    }

    pub fn get_cert_der(&self) -> Result<Vec<u8>, Error> {
        let x509_cert = self
            .request
            .signature
            .as_ref()
            .ok_or(Error::NoSignature)?
            .key_info
            .as_ref()
            .map(|ki| ki.iter().next())
            .unwrap_or(None)
            .ok_or(Error::NoKeyInfo)?
            .x509_data
            .as_ref()
            .map(|d| d.certificate.as_ref())
            .unwrap_or(None)
            .ok_or(Error::NoCertificate)?;

        let x509_cert = crypto::decode_x509_cert(x509_cert.as_str())
            .map_err(|_| Error::InvalidCertificateEncoding)?;
        Ok(x509_cert)
    }

    pub fn try_verify_self_signed(self) -> Result<VerifiedAuthnRequest, Error> {
        let cert = self.get_cert_der()?;
        self.try_verify_with_cert(&cert)
    }

    pub fn try_verify_with_cert(self, der_cert: &[u8]) -> Result<VerifiedAuthnRequest, Error> {
        verify_signed_xml(self.xml.as_bytes(), der_cert, Some("ID"))?;
        Ok(VerifiedAuthnRequest(self.request))
    }
}

pub struct VerifiedAuthnRequest(AuthnRequest);

impl std::ops::Deref for VerifiedAuthnRequest {
    type Target = AuthnRequest;
    fn deref(&self) -> &AuthnRequest {
        &self.0
    }
}
