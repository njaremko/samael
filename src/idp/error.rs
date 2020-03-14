use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    NoSignature,
    NoKeyInfo,
    NoCertificate,
    NoSPSsoDescriptors,
    SignatureFailed,
    UnexpectedError,
    MismatchedCertificate,
    InvalidCertificateEncoding,

    MissingAudience,
    MissingAcsUrl,
    NonHttpPostBindingUnsupported,

    MissingAuthnRequestSubjectNameID,
    MissingAuthnRequestIssuer,

    #[snafu(display("Invalid AuthnRequest: {}", error))]
    InvalidAuthnRequest {
        error: crate::schema::authn_request::Error,
    },

    #[snafu(display("OpenSSL Error: {}", stack))]
    OpenSSLError {
        stack: openssl::error::ErrorStack,
    },

    #[snafu(display("Verification Error: {}", error))]
    VerificationError {
        error: crate::crypto::Error,
    },
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        Error::OpenSSLError { stack: error }
    }
}

impl From<crate::crypto::Error> for Error {
    fn from(error: crate::crypto::Error) -> Self {
        Error::VerificationError { error }
    }
}

impl From<crate::schema::authn_request::Error> for Error {
    fn from(error: crate::schema::authn_request::Error) -> Self {
        Error::InvalidAuthnRequest { error }
    }
}
