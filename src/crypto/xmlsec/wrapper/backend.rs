//!
//! Abstraction over API differences between dynamic loading and static OpenSSL
//!

#[cfg(xmlsec_dynamic)]
use crate::crypto::xmlsec::wrapper::bindings as backend_inner;

#[cfg(xmlsec_static)]
mod backend_inner {
    pub use crate::crypto::xmlsec::wrapper::bindings::{
        xmlSecOpenSSLAppInit as xmlSecCryptoAppInit,
        xmlSecOpenSSLAppKeyCertLoad as xmlSecCryptoAppKeyCertLoad,
        xmlSecOpenSSLAppKeyCertLoadMemory as xmlSecCryptoAppKeyCertLoadMemory,
        xmlSecOpenSSLAppKeyLoadMemory as xmlSecCryptoAppKeyLoadMemory,
        xmlSecOpenSSLAppShutdown as xmlSecCryptoAppShutdown, xmlSecOpenSSLInit as xmlSecCryptoInit,
        xmlSecOpenSSLShutdown as xmlSecCryptoShutdown,
    };
}

pub use backend_inner::*;
