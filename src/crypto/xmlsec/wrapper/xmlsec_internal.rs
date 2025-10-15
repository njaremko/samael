//!
//! Central XmlSec1 Context
//!
use crate::crypto::xmlsec::wrapper::bindings;

use lazy_static::lazy_static;

use super::backend;
use super::error::XmlSecError;
use super::XmlSecResult;
use std::convert::TryInto;
use std::ptr::null;
use std::sync::Mutex;

lazy_static! {
    static ref XMLSEC: Mutex<Option<XmlSecContext>> = Mutex::new(None);
}

pub fn guarantee_xmlsec_init() -> XmlSecResult<()> {
    let mut inner = XMLSEC
        .lock()
        .expect("Unable to lock global wrapper initalization wrapper");

    if inner.is_none() {
        *inner = Some(XmlSecContext::new()?);
    }

    Ok(())
}

/// XmlSec Global Context
///
/// This object initializes the underlying wrapper global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
pub struct XmlSecContext {}

impl XmlSecContext {
    /// Runs wrapper initialization and returns instance of itself.
    pub fn new() -> XmlSecResult<Self> {
        unsafe {
            libxml::bindings::xmlInitParser();
        }

        init_xmlsec()?;
        init_crypto_app()?;
        init_crypto()?;

        Ok(Self {})
    }
}

impl Drop for XmlSecContext {
    fn drop(&mut self) {
        cleanup_crypto();
        cleanup_crypto_app();
        cleanup_xmlsec();
    }
}

/// Init wrapper library
fn init_xmlsec() -> XmlSecResult<()> {
    let rc = unsafe {
        bindings::xmlSecCheckVersionExt(
            bindings::XMLSEC_VERSION_MAJOR.try_into().unwrap(),
            bindings::XMLSEC_VERSION_MINOR.try_into().unwrap(),
            bindings::XMLSEC_VERSION_SUBMINOR.try_into().unwrap(),
            bindings::xmlSecCheckVersionMode_xmlSecCheckVersionABICompatible,
        )
    };

    if rc < 0 {
        return Err(XmlSecError::XmlSecAbiMismatch);
    }

    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        Err(XmlSecError::XmlSecInitError)
    } else {
        Ok(())
    }
}

/// Load default crypto engine if we are supporting dynamic loading for
/// wrapper-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding wrapper-crypto library.
fn init_crypto_app() -> XmlSecResult<()> {
    #[cfg(xmlsec_dynamic)]
    {
        let rc = unsafe { backend::xmlSecCryptoDLLoadLibrary(null()) };
        if rc < 0 {
            return Err(XmlSecError::CryptoLoadLibraryError);
        }
    }

    let rc = unsafe { backend::xmlSecCryptoAppInit(null()) };

    if rc < 0 {
        Err(XmlSecError::CryptoInitOpenSSLAppError)
    } else {
        Ok(())
    }
}

/// Init wrapper-crypto library
fn init_crypto() -> XmlSecResult<()> {
    let rc = unsafe { backend::xmlSecCryptoInit() };

    if rc < 0 {
        Err(XmlSecError::CryptoInitOpenSSLError)
    } else {
        Ok(())
    }
}

/// Shutdown wrapper-crypto library
fn cleanup_crypto() {
    unsafe { backend::xmlSecCryptoShutdown() };
}

/// Shutdown crypto library
fn cleanup_crypto_app() {
    unsafe { backend::xmlSecCryptoAppShutdown() };
}

/// Shutdown wrapper library
fn cleanup_xmlsec() {
    unsafe { bindings::xmlSecShutdown() };
}
