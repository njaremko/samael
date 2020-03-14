//!
//! Central XmlSec1 Context
//!
use crate::bindings;

use lazy_static::lazy_static;

use super::error::XmlSecError;
use super::XmlSecResult;
use std::ffi::CString;
use std::ptr::null;
use std::sync::Mutex;

lazy_static! {
    static ref XMLSEC: Mutex<Option<XmlSecContext>> = Mutex::new(None);
}

pub fn guarantee_xmlsec_init() -> XmlSecResult<()> {
    let mut inner = XMLSEC
        .lock()
        .expect("Unable to lock global xmlsec initalization wrapper");

    if inner.is_none() {
        *inner = Some(XmlSecContext::new()?);
    }

    Ok(())
}

/// XmlSec Global Context
///
/// This object initializes the underlying xmlsec global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
pub struct XmlSecContext {}

impl XmlSecContext {
    /// Runs xmlsec initialization and returns instance of itself.
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

/// Init xmlsec library
fn init_xmlsec() -> XmlSecResult<()> {
    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        Err(XmlSecError::XmlSecInitError)
    } else {
        Ok(())
    }
}

/// Load default crypto engine if we are supporting dynamic loading for
/// xmlsec-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding xmlsec-crypto library.
fn init_crypto_app() -> XmlSecResult<()> {
    let rc = unsafe { bindings::xmlSecOpenSSLAppInit(null()) };

    if rc < 0 {
        Err(XmlSecError::CryptoInitOpenSSLAppError)
    } else {
        Ok(())
    }
}

/// Init xmlsec-crypto library
fn init_crypto() -> XmlSecResult<()> {
    let rc = unsafe { bindings::xmlSecOpenSSLInit() };

    if rc < 0 {
        Err(XmlSecError::CryptoInitOpenSSLError)
    } else {
        Ok(())
    }
}

/// Shutdown xmlsec-crypto library
fn cleanup_crypto() {
    unsafe { bindings::xmlSecOpenSSLShutdown() };
}

/// Shutdown crypto library
fn cleanup_crypto_app() {
    unsafe { bindings::xmlSecOpenSSLAppShutdown() };
}

/// Shutdown xmlsec library
fn cleanup_xmlsec() {
    unsafe { bindings::xmlSecShutdown() };
}
