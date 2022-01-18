//!
//! Wrapper for XmlSec Signature Context
//!
use crate::bindings;

use super::XmlDocument;
use super::XmlSecError;
use super::XmlSecKey;
use super::XmlSecResult;

use std::os::raw::c_uchar;
use std::ptr::{null, null_mut};

/// Signature signing/veryfying context
pub struct XmlSecSignatureContext {
    ctx: *mut bindings::xmlSecDSigCtx,
}

impl XmlSecSignatureContext {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> XmlSecResult<Self> {
        let _init = super::xmlsec::guarantee_xmlsec_init()?;

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(null_mut()) };

        if ctx.is_null() {
            return Err(XmlSecError::ContextInitError);
        }

        Ok(Self { ctx })
    }

    /// Sets the key to use for signature or verification. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;

        unsafe {
            if !(*self.ctx).signKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).signKey));
            }

            (*self.ctx).signKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    #[allow(unused)]
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            if !(*self.ctx).signKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).signKey);

                (*self.ctx).signKey = null_mut();

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

impl XmlSecSignatureContext {
    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !(*self.ctx).signKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn sign_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<()> {
        let rc = unsafe { bindings::xmlSecDSigCtxSign(self.ctx, node) };

        if rc < 0 {
            Err(XmlSecError::SigningError)
        } else {
            Ok(())
        }
    }

    fn verify_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<bool> {
        let rc = unsafe { bindings::xmlSecDSigCtxVerify(self.ctx, node) };

        if rc < 0 {
            return Err(XmlSecError::VerifyError);
        }

        match unsafe { (*self.ctx).status } {
            bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => Ok(true),
            _ => Ok(false),
        }
    }
}

impl Drop for XmlSecSignatureContext {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecDSigCtxDestroy(self.ctx) };
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
