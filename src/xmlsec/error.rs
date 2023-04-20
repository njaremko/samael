//!
//! XmlSec High Level Error handling
//!

/// Wrapper project-wide Result typealias.
pub type XmlSecResult<T> = Result<T, XmlSecError>;

/// Wrapper project-wide Errors enumeration.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum XmlSecError {
    XmlSecAbiMismatch,
    XmlSecInitError,
    ContextInitError,
    CryptoInitOpenSSLError,
    CryptoInitOpenSSLAppError,
    #[cfg(xmlsec_dynamic)]
    CryptoLoadLibraryError,

    InvalidInputString,

    SetKeyError,
    KeyNotLoaded,
    KeyLoadError,
    CertLoadError,

    RootNotFound,
    NodeNotFound,
    NotASignatureNode,

    SigningError,
    VerifyError,
}

impl std::fmt::Display for XmlSecError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::XmlSecInitError => write!(fmt, "Internal XmlSec Init Error"),
            Self::XmlSecAbiMismatch => write!(fmt, "XmlSec ABI version mismatch"),
            Self::CryptoInitOpenSSLError => {
                write!(fmt, "Internal XmlSec Crypto OpenSSL Init Error")
            }
            Self::CryptoInitOpenSSLAppError => {
                write!(fmt, "Internal XmlSec Crypto OpenSSLApp Init Error")
            }
            #[cfg(xmlsec_dynamic)]
            Self::CryptoLoadLibraryError => {
                write!(fmt, "XmlSec failed to load default crypto backend")
            }
            Self::ContextInitError => write!(fmt, "Internal XmlSec Context Error"),

            Self::InvalidInputString => write!(fmt, "Input value is not a valid string"),

            Self::SetKeyError => write!(fmt, "Key could not be set"),
            Self::KeyNotLoaded => write!(fmt, "Key has not yet been loaded and is required"),
            Self::KeyLoadError => write!(fmt, "Failed to load key"),
            Self::CertLoadError => write!(fmt, "Failed to load certificate"),

            Self::RootNotFound => write!(fmt, "Failed to find document root"),
            Self::NodeNotFound => write!(fmt, "Failed to find node"),
            Self::NotASignatureNode => write!(fmt, "Node is not a signature node"),

            Self::SigningError => {
                write!(fmt, "An error has ocurred while attemting to sign document")
            }
            Self::VerifyError => write!(fmt, "Verification failed"),
        }
    }
}

impl std::error::Error for XmlSecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
