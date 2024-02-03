use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("")]
    NoSignature,
    #[error("")]
    NoKeyInfo,
    #[error("")]
    NoCertificate,
    #[error("")]
    NoSPSsoDescriptors,
    #[error("")]
    SignatureFailed,
    #[error("")]
    UnexpectedError,
    #[error("")]
    MismatchedCertificate,
    #[error("")]
    InvalidCertificateEncoding,

    #[error("")]
    MissingAudience,
    #[error("")]
    MissingAcsUrl,
    #[error("")]
    NonHttpPostBindingUnsupported,

    #[error("")]
    MissingAuthnRequestSubjectNameID,
    #[error("")]
    MissingAuthnRequestIssuer,

    #[error("Invalid AuthnRequest: {}", error)]
    InvalidAuthnRequest {
        #[from]
        error: crate::schema::authn_request::Error,
    },

    #[cfg(feature = "openssl")]
    #[error("OpenSSL Error: {}", stack)]
    OpenSSLError {
        #[from]
        stack: openssl::error::ErrorStack,
    },

    #[error("Verification Error: {}", error)]
    VerificationError {
        #[from]
        error: crate::crypto::Error,
    },

    Unknown,
}
