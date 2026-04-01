//!
//! Wrapper for XmlSec Signature Context
//!
use crate::crypto::xmlsec::wrapper::bindings;

use super::XmlSecKey;
use super::XmlSecResult;
use super::{XmlDocument, XmlSecError};

use std::os::raw::c_uchar;
use std::ptr::{null, null_mut, NonNull};

/// The verified data for a single `<ds:Reference>`.
pub struct VerifiedReference {
    /// The reference URI attribute, if present.
    pub uri: Option<String>,
    /// The canonicalized XML that xmlsec verified for this reference.
    pub predigest_xml: String,
}

/// Signature signing/verifying context
pub struct XmlSecSignatureContext {
    ctx: NonNull<bindings::xmlSecDSigCtx>,
}

impl XmlSecSignatureContext {
    /// Builds a context, ensuring wrapper is initialized.
    pub fn new() -> XmlSecResult<Self> {
        super::xmlsec_internal::guarantee_xmlsec_init()?;

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(null_mut()) };
        let ctx = NonNull::new(ctx).ok_or(XmlSecError::ContextInitError)?;

        Ok(Self { ctx })
    }

    /// Builds a context with specific flags.
    pub fn new_with_flags(flags: u32) -> XmlSecResult<Self> {
        let mut ctx = Self::new()?;
        unsafe {
            ctx.ctx.as_mut().flags |= flags;
        }
        Ok(ctx)
    }

    /// Retrieves the verified references from `<ds:SignedInfo>`.
    pub fn get_verified_references(&self) -> XmlSecResult<Vec<VerifiedReference>> {
        let mut result = Vec::new();

        unsafe {
            let list_ptr = &self.ctx.as_ref().signedInfoReferences as *const bindings::xmlSecPtrList
                as *mut bindings::xmlSecPtrList;
            let count = bindings::xmlSecPtrListGetSize(list_ptr);

            for i in 0..count {
                let ref_ctx_ptr = bindings::xmlSecPtrListGetItem(list_ptr, i);
                if ref_ctx_ptr.is_null() {
                    return Err(XmlSecError::SigningError);
                }

                let ref_ctx_ptr = ref_ctx_ptr as bindings::xmlSecDSigReferenceCtxPtr;
                let ref_ctx = &*ref_ctx_ptr;

                if ref_ctx.status != bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded {
                    return Err(XmlSecError::VerifyError);
                }

                let uri = if ref_ctx.uri.is_null() {
                    None
                } else {
                    let uri_cstr = std::ffi::CStr::from_ptr(ref_ctx.uri as *const std::ffi::c_char);
                    Some(
                        uri_cstr
                            .to_str()
                            .map_err(|_| XmlSecError::InvalidInputString)?
                            .to_string(),
                    )
                };

                let predigest_buf = bindings::xmlSecDSigReferenceCtxGetPreDigestBuffer(ref_ctx_ptr);
                if predigest_buf.is_null() {
                    return Err(XmlSecError::VerifyError);
                }

                let data_ptr = bindings::xmlSecBufferGetData(predigest_buf);
                let data_size = bindings::xmlSecBufferGetSize(predigest_buf);
                let predigest_xml = predigest_xml_from_raw_buffer(data_ptr, data_size as usize)?;

                result.push(VerifiedReference { uri, predigest_xml });
            }
        }

        Ok(result)
    }

    /// Retrieves the URI strings from the verified reference contexts.
    pub fn get_verified_reference_uris(&self) -> XmlSecResult<Vec<String>> {
        Ok(self
            .get_verified_references()?
            .into_iter()
            .filter_map(|reference| reference.uri)
            .collect())
    }

    /// Retrieves the pre-digest data from the first and only verified reference.
    pub fn get_predigest_data(&self) -> XmlSecResult<String> {
        let mut references = self.get_verified_references()?;
        if references.len() != 1 {
            return Err(XmlSecError::SigningError);
        }

        Ok(references.remove(0).predigest_xml)
    }

    /// Sets the key to use for signature or verification. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;

        unsafe {
            let ctx = self.ctx.as_mut();
            if !ctx.signKey.is_null() {
                old = Some(XmlSecKey::from_ptr(ctx.signKey));
            }

            ctx.signKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    #[allow(unused)]
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            let ctx = self.ctx.as_mut();
            if ctx.signKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr(ctx.signKey);

                ctx.signKey = null_mut();

                Some(key)
            }
        }
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to sign it. For this to work it has to have a properly structured
    /// `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn sign_document(&self, doc: &XmlDocument, id_attr: Option<&str>) -> XmlSecResult<()> {
        self.key_is_set()?;

        let doc_ptr = doc.doc_ptr();
        let root = if let Some(root) = doc.get_root_element() {
            root
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let root_ptr = root.node_ptr() as *mut bindings::xmlNode;

        if let Some(id_attr) = id_attr {
            let cid =
                std::ffi::CString::new(id_attr).map_err(|_| XmlSecError::InvalidInputString)?;

            unsafe {
                let mut list = [cid.as_bytes().as_ptr(), null()];
                bindings::xmlSecAddIDs(
                    doc_ptr as *mut bindings::xmlDoc,
                    root_ptr,
                    list.as_mut_ptr(),
                );
            }
        }

        let signode = find_signode(root_ptr)?;
        self.sign_node_raw(signode)
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to verify its signature. For this to work it has to have a properly
    /// structured and signed `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with
    /// [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_document(&self, doc: &XmlDocument, id_attr: Option<&str>) -> XmlSecResult<bool> {
        self.key_is_set()?;

        let doc_ptr = doc.doc_ptr();
        let root = if let Some(root) = doc.get_root_element() {
            root
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let root_ptr = root.node_ptr() as *mut bindings::xmlNode;

        if let Some(id_attr) = id_attr {
            let cid =
                std::ffi::CString::new(id_attr).map_err(|_| XmlSecError::InvalidInputString)?;

            unsafe {
                let mut list = [cid.as_bytes().as_ptr(), null()];
                bindings::xmlSecAddIDs(
                    doc_ptr as *mut bindings::xmlDoc,
                    root_ptr,
                    list.as_mut_ptr(),
                );
            }
        }

        let signode = find_signode(root_ptr)?;
        self.verify_node_raw(signode)
    }

    /// Takes a `<dsig:Signature>` [`Node`][xmlnode] and attempts to verify it. For this to work, a XmlSecKey must have
    /// been previously set with [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set, the node is not a signature node or the document is malformed.
    ///
    /// [xmlnode]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Node.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_node(&self, sig_node: &libxml::tree::Node) -> XmlSecResult<bool> {
        self.key_is_set()?;
        if let Some(ns) = sig_node.get_namespace() {
            if ns.get_href() != "http://www.w3.org/2000/09/xmldsig#"
                || sig_node.get_name() != "Signature"
            {
                return Err(XmlSecError::NotASignatureNode);
            }
        } else {
            return Err(XmlSecError::NotASignatureNode);
        }

        let node_ptr = sig_node.node_ptr();
        self.verify_node_raw(node_ptr as *mut bindings::xmlNode)
    }
}

fn predigest_xml_from_raw_buffer(
    data_ptr: *const c_uchar,
    data_size: usize,
) -> XmlSecResult<String> {
    if data_size == 0 {
        return Ok(String::new());
    }

    if data_ptr.is_null() {
        return Err(XmlSecError::VerifyError);
    }

    let data_slice = unsafe { std::slice::from_raw_parts(data_ptr, data_size) };
    let predigest_xml = std::str::from_utf8(data_slice)
        .map_err(|_| XmlSecError::InvalidInputString)?
        .to_string();
    Ok(predigest_xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predigest_xml_from_raw_buffer_accepts_empty_buffers() {
        let predigest_xml = predigest_xml_from_raw_buffer(std::ptr::null(), 0)
            .expect("zero-length pre-digest buffers should be accepted");

        assert!(predigest_xml.is_empty());
    }

    #[test]
    fn predigest_xml_from_raw_buffer_rejects_invalid_utf8() {
        let bytes = [0xff];
        let error = predigest_xml_from_raw_buffer(bytes.as_ptr(), bytes.len())
            .expect_err("non-utf8 pre-digest buffers should be rejected");

        assert!(matches!(error, XmlSecError::InvalidInputString));
    }
}

impl XmlSecSignatureContext {
    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !self.ctx.as_ref().signKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn sign_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<()> {
        let rc = unsafe { bindings::xmlSecDSigCtxSign(self.ctx.as_ptr(), node) };

        if rc < 0 {
            Err(XmlSecError::SigningError)
        } else {
            Ok(())
        }
    }

    fn verify_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<bool> {
        let rc = unsafe { bindings::xmlSecDSigCtxVerify(self.ctx.as_ptr(), node) };

        if rc < 0 {
            return Err(XmlSecError::VerifyError);
        }

        match unsafe { self.ctx.as_ref().status } {
            bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => Ok(true),
            _ => Ok(false),
        }
    }
}

impl Drop for XmlSecSignatureContext {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecDSigCtxDestroy(self.ctx.as_ptr()) };
    }
}

fn find_signode(tree: *mut bindings::xmlNode) -> XmlSecResult<*mut bindings::xmlNode> {
    let signode = unsafe {
        bindings::xmlSecFindNode(
            tree,
            &bindings::xmlSecNodeSignature as *const c_uchar,
            &bindings::xmlSecDSigNs as *const c_uchar,
        )
    };

    if signode.is_null() {
        return Err(XmlSecError::NodeNotFound);
    }

    Ok(signode)
}
