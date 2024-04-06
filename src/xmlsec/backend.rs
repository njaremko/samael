//!
//! Abstraction over API differences between dynamic loading and static OpenSSL
//!

#[cfg(xmlsec_dynamic)]
use crate::bindings as backend;

#[cfg(xmlsec_static)]
mod backend {
    pub use crate::bindings::{
        xmlSecOpenSSLAppInit as xmlSecCryptoAppInit,
        // xmlSecOpenSSLAppKeyCertLoad as xmlSecCryptoAppKeyCertLoad,
        // xmlSecOpenSSLAppKeyCertLoadMemory as xmlSecCryptoAppKeyCertLoadMemory,
        xmlSecOpenSSLAppKeyLoadMemory as xmlSecCryptoAppKeyLoadMemory,
        xmlSecOpenSSLAppShutdown as xmlSecCryptoAppShutdown, xmlSecOpenSSLInit as xmlSecCryptoInit,
        xmlSecOpenSSLShutdown as xmlSecCryptoShutdown,
    };
}

pub use backend::*;
