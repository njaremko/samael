//!
//! Wrapper for XmlSec Key and Certificate management Context
//!
use crate::bindings;

use super::error::XmlSecError;
use super::error::XmlSecResult;
use super::xmlsec;

use std::ptr::null;
use std::ptr::null_mut;

/// x509 key format.
#[allow(dead_code)]
#[allow(missing_docs)]
#[repr(u32)]
pub enum XmlSecKeyFormat {
    Unknown = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatUnknown,
    Binary = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatBinary,
    Pem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
    Der = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatDer,
    Pkcs8Pem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Pem,
    Pkcs8Der = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Der,
    Pkcs12 = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs12,
    CertPem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
    CertDer = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertDer,
}

/// Key with which we sign/verify signatures or encrypt data. Used by [`XmlSecSignatureContext`][sigctx].
///
/// [sigctx]: struct.XmlSecSignatureContext.html
#[derive(Debug)]
pub struct XmlSecKey(*mut bindings::xmlSecKey);

impl XmlSecKey {
    /// Load key from buffer in memory, specifying format and optionally the password required to decrypt/unlock.
    pub fn from_memory(buffer: &[u8], format: XmlSecKeyFormat) -> XmlSecResult<Self> {
        let _ctx = xmlsec::guarantee_xmlsec_init()?;

        // Load key from buffer
        let key = unsafe {
            bindings::xmlSecOpenSSLAppKeyLoadMemory(
                buffer.as_ptr(),
                buffer.len().try_into().expect("Key buffer length overflow"),
                format as u32,
                null(),
                null_mut(),
                null_mut(),
            )
        };

        if key.is_null() {
            return Err(XmlSecError::KeyLoadError);
        }

        Ok(Self { 0: key })
    }

    /// Create from raw pointer to an underlying xmlsec key structure. Henceforth its lifetime will be managed by this
    /// object.
    pub unsafe fn from_ptr(ptr: *mut bindings::xmlSecKey) -> Self {
        Self { 0: ptr }
    }

    /// Leak the internal resource. This is needed by [`XmlSecSignatureContext`][sigctx], since xmlsec takes over the
    /// lifetime management of the underlying resource when setting it as the active key for signature signing or
    /// verification.
    ///
    /// [sigctx]: struct.XmlSecSignatureContext.html
    pub unsafe fn leak(key: Self) -> *mut bindings::xmlSecKey {
        let ptr = key.0;

        std::mem::forget(key);

        ptr
    }
}

impl PartialEq for XmlSecKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 // compare pointer addresses
    }
}

impl Eq for XmlSecKey {}

impl Clone for XmlSecKey {
    fn clone(&self) -> Self {
        let new = unsafe { bindings::xmlSecKeyDuplicate(self.0) };

        Self { 0: new }
    }
}

impl Drop for XmlSecKey {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecKeyDestroy(self.0) };
    }
}
