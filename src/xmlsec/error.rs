//!
//! XmlSec High Level Error handling
//!

use snafu::Snafu;

/// Wrapper project-wide Result typealias.
pub type XmlSecResult<T> = Result<T, XmlSecError>;

/// Wrapper project-wide Errors enumeration.
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
pub enum XmlSecError {
    #[snafu(display("Internal XmlSec Init Error"))]
    XmlSecInitError,
    #[snafu(display("Internal XmlSec Context Error"))]
    ContextInitError,
    #[snafu(display("Internal XmlSec Crypto OpenSSL Init Error"))]
    CryptoInitOpenSSLError,
    #[snafu(display("Internal XmlSec Crypto OpenSSLApp Init Error"))]
    CryptoInitOpenSSLAppError,

    #[snafu(display("Input value is not a valid string"))]
    InvalidInputString,

    #[snafu(display("Key could not be set"))]
    SetKeyError,
    #[snafu(display("Key has not yet been loaded and is required"))]
    KeyNotLoaded,
    #[snafu(display("Failed to load key"))]
    KeyLoadError,
    #[snafu(display("Failed to load certificate"))]
    CertLoadError,

    #[snafu(display("Failed to find document root"))]
    RootNotFound,
    #[snafu(display("Failed to find node"))]
    NodeNotFound,
    #[snafu(display("Node is not a signature node"))]
    NotASignatureNode,

    #[snafu(display("An error has occurred while attempting to sign document"))]
    SigningError,
    #[snafu(display("Verification failed"))]
    VerifyError,
}
