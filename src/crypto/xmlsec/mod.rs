use std::collections::HashMap;
use thiserror::Error;
use super::CryptoError;

use libxml::parser::Parser as XmlParser;
use openssl::symm::{Cipher, Crypter, Mode};
use std::ffi::CString;
use libxml::parser::XmlParseError;
use openssl::error::ErrorStack;
use crate::schema::CipherValue;

mod xmlsec;
use xmlsec::{XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext};

const XMLNS_XML_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLNS_SIGVER: &str = "urn:urn-5:08Z8lPlI4JVjifINTfCtfelirUo";
const ATTRIB_SIGVER: &str = "sv";
const VALUE_SIGVER: &str = "verified";

#[derive(Debug, Error)]
pub enum XmlSecProviderError {
    #[error("Encountered an invalid signature")]
    InvalidSignature,

    #[error("base64 decoding Error: {}", error)]
    Base64Error {
        #[from]
        error: base64::DecodeError,
    },

    #[error("The given XML is missing a root element")]
    XmlMissingRootElement,

    #[error("xml sec Error: {}", error)]
    XmlParseError {
        #[from]
        error: XmlParseError,
    },

    #[error("xml sec Error: {}", error)]
    XmlSecError {
        #[from]
        error: xmlsec::XmlSecError,
    },

    #[error("failed to remove attribute: {}", error)]
    XmlAttributeRemovalError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to define namespace: {}", error)]
    XmlNamespaceDefinitionError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("OpenSSL error stack: {}", error)]
    OpenSSLError {
        #[from]
        error: ErrorStack,
    },
}

impl From<xmlsec::XmlSecError> for CryptoError {
    fn from(value: xmlsec::XmlSecError) -> Self {
        CryptoError::CryptoProviderError(Box::new(value))
    }
}

impl From<XmlSecProviderError> for CryptoError {
    fn from(value: XmlSecProviderError) -> Self {
        CryptoError::CryptoProviderError(Box::new(value))
    }
}

impl From<ErrorStack> for CryptoError {
    fn from(value: ErrorStack) -> Self {
        CryptoError::CryptoProviderError(Box::new(value))
    }
}

impl From<XmlParseError> for CryptoError {
    fn from(value: XmlParseError) -> Self {
        CryptoError::CryptoProviderError(Box::new(value))
    }
}

pub struct XmlSec;

impl super::CryptoProvider for XmlSec {

    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        x509_cert_der: &[u8],
        id_attribute: Option<&str>,
    ) -> Result<(), CryptoError> {
        let parser = XmlParser::default();
        let document = parser.parse_string(xml)?;

        let key = XmlSecKey::from_memory(x509_cert_der, XmlSecKeyFormat::CertDer)?;
        let mut context = XmlSecSignatureContext::new()?;
        context.insert_key(key);

        let valid = context.verify_document(&document, id_attribute)?;

        if !valid {
            return Err(CryptoError::InvalidSignature);
        }

        Ok(())
    }

    fn decrypt_assertion_key_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> Result<Vec<u8>, CryptoError> {
        use openssl::rsa::Padding;

        let padding = match method {
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Padding::PKCS1_OAEP,
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5" => Padding::PKCS1,
            _ => {
                return Err(CryptoError::EncryptedAssertionKeyMethodUnsupported {
                    method: method.to_string(),
                });
            }
        };

        let encrypted_key =
            openssl::base64::decode_block(&cipher_value.value.lines().collect::<String>())?;
        let pkey_size = decryption_key.size();
        let mut decrypted_key = vec![0u8; pkey_size];
        let rsa = decryption_key.rsa()?;
        let i = rsa.private_decrypt(&encrypted_key, &mut decrypted_key, padding)?;
        Ok(decrypted_key[0..i].to_vec())
    }

    fn decrypt_assertion_value_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use openssl::symm::Cipher;

        let encoded_value =
            openssl::base64::decode_block(&cipher_value.value.lines().collect::<String>())?;

        let plaintext = match method {
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => {
                let cipher = Cipher::aes_128_cbc();
                let iv_len = cipher.iv_len().unwrap();
                decrypt(
                    cipher,
                    decryption_key,
                    Some(&encoded_value[0..iv_len]),
                    &encoded_value[iv_len..],
                )?
            }
            "http://www.w3.org/2009/xmlenc11#aes128-gcm" => {
                let cipher = Cipher::aes_128_gcm();
                let iv_len = cipher.iv_len().unwrap();
                let tag_len = 16usize;
                let data_end = encoded_value.len() - tag_len;
                decrypt_aead(
                    cipher,
                    decryption_key,
                    Some(&encoded_value[0..iv_len]),
                    &[],
                    &encoded_value[iv_len..data_end],
                    &encoded_value[data_end..],
                )?
            }
            _ => {
                return Err(CryptoError::EncryptedAssertionValueMethodUnsupported {
                    method: method.to_string(),
                });
            }
        };

        Ok(plaintext)

    }

    fn sign_xml<Bytes: AsRef<[u8]>>(xml: Bytes, private_key_der: &[u8]) -> Result<String, CryptoError> {
        let parser = XmlParser::default();
        let document = parser.parse_string(xml)?;

        let key = XmlSecKey::from_memory(private_key_der, XmlSecKeyFormat::Der)?;
        let mut context = XmlSecSignatureContext::new()?;
        context.insert_key(key);

        context.sign_document(&document, Some("ID"))?;

        Ok(document.to_string())
    }
}


/// Searches the document for all attributes named `ID` and stores them and their values in the XML
/// document's internal ID table.
///
/// This is necessary for signature verification to successfully follow the references from a
/// `<dsig:Signature>` element to the element it has signed.
fn collect_id_attributes(doc: &mut libxml::tree::Document) -> Result<(), XmlSecProviderError> {
    const ID_STR: &str = "ID";
    let id_attr_name = CString::new(ID_STR).unwrap();

    let mut nodes_to_visit = Vec::new();
    if let Some(root_elem) = doc.get_root_element() {
        nodes_to_visit.push(root_elem);
    }
    while let Some(node) = nodes_to_visit.pop() {
        if let Some(id_value) = node.get_attribute(ID_STR) {
            let id_value_cstr = CString::new(id_value).unwrap();
            let node_ptr = node.node_ptr();
            unsafe {
                let attr =
                    libxml::bindings::xmlHasProp(node_ptr, id_attr_name.as_ptr() as *const u8);
                assert!(!attr.is_null());
                libxml::bindings::xmlAddID(
                    std::ptr::null_mut(),
                    doc.doc_ptr(),
                    id_value_cstr.as_ptr() as *const u8,
                    attr,
                );
            }
        }

        for child in node.get_child_elements() {
            nodes_to_visit.push(child);
        }
    }

    Ok(())
}

/// Finds and returns all `<dsig:Signature>` elements in the subtree rooted at the given node.
fn find_signature_nodes(node: &libxml::tree::Node) -> Vec<libxml::tree::Node> {
    let mut ret = Vec::new();

    if let Some(ns) = &node.get_namespace() {
        if ns.get_href() == XMLNS_XML_DSIG && node.get_name() == "Signature" {
            ret.push(node.clone());
        }
    }

    for child in node.get_child_elements() {
        let mut children = find_signature_nodes(&child);
        ret.append(&mut children);
    }

    ret
}

/// Removes all signature-verified attributes ([`ATTRIB_SIGVER`] in the namespace [`XMLNS_SIGVER`])
/// from all elements in the subtree rooted at the given node.
pub fn remove_signature_verified_attributes(node: &mut libxml::tree::Node) -> Result<(), XmlSecProviderError> {
    node.remove_attribute_ns(ATTRIB_SIGVER, XMLNS_SIGVER)
        .map_err(|err| XmlSecProviderError::XmlAttributeRemovalError { error: err })?;
    for mut child_elem in node.get_child_elements() {
        remove_signature_verified_attributes(&mut child_elem)?;
    }
    Ok(())
}

/// Obtains the first child element of the given node that has the given name and namespace.
fn get_first_child_name_ns(
    node: &libxml::tree::Node,
    name: &str,
    ns: &str,
) -> Option<libxml::tree::Node> {
    let mut found_node = None;
    for child in node.get_child_elements() {
        if let Some(child_ns) = child.get_namespace() {
            if child_ns.get_href() != ns {
                continue;
            }
        } else {
            continue;
        }

        if child.get_name() == name {
            found_node = Some(child);
            break;
        }
    }
    found_node
}

/// Searches the subtree rooted at the given node and returns the elements which match the given
/// predicate.
fn get_elements_by_predicate<F: FnMut(&libxml::tree::Node) -> bool>(
    elem: &libxml::tree::Node,
    mut pred: F,
) -> Vec<libxml::tree::Node> {
    let mut nodes_to_visit = Vec::new();
    let mut nodes = Vec::new();
    nodes_to_visit.push(elem.clone());
    while let Some(node) = nodes_to_visit.pop() {
        if pred(&node) {
            nodes.push(node.clone());
        }
        let mut children = node.get_child_elements();
        nodes_to_visit.append(&mut children);
    }
    nodes
}

/// Searches for and returns the element with the given pointer value from the subtree rooted at the
/// given node.
fn get_node_by_ptr(
    elem: &libxml::tree::Node,
    ptr: *const libxml::bindings::xmlNode,
) -> Option<libxml::tree::Node> {
    let mut elems = get_elements_by_predicate(elem, |node| {
        let node_ptr = node.node_ptr() as *const _;
        node_ptr == ptr
    });
    let elem = elems.drain(..).next();
    elem
}

struct XPathContext {
    pub pointer: libxml::bindings::xmlXPathContextPtr,
}
impl Drop for XPathContext {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeContext(self.pointer) }
    }
}

struct XPathObject {
    pub pointer: libxml::bindings::xmlXPathObjectPtr,
}
impl Drop for XPathObject {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeObject(self.pointer) }
    }
}

/// Searches for and returns the element at the root of the subtree signed by the given signature
/// node.
fn get_signed_node(
    signature_node: &libxml::tree::Node,
    doc: &libxml::tree::Document,
) -> Option<libxml::tree::Node> {
    let object_elem_opt = get_first_child_name_ns(signature_node, "Object", XMLNS_XML_DSIG);
    if let Some(object_elem) = object_elem_opt {
        return Some(object_elem);
    }

    let sig_info_elem_opt = get_first_child_name_ns(signature_node, "SignedInfo", XMLNS_XML_DSIG);
    if let Some(sig_info_elem) = sig_info_elem_opt {
        let ref_elem_opt = get_first_child_name_ns(&sig_info_elem, "Reference", XMLNS_XML_DSIG);
        if let Some(ref_elem) = ref_elem_opt {
            if let Some(uri) = ref_elem.get_attribute("URI") {
                if let Some(stripped) = uri.strip_prefix('#') {
                    // prepare a XPointer context
                    let c_uri = CString::new(stripped).unwrap();
                    let ctx_ptr = unsafe {
                        libxml::bindings::xmlXPtrNewContext(
                            doc.doc_ptr(),
                            signature_node.node_ptr(),
                            std::ptr::null_mut(),
                        )
                    };
                    if ctx_ptr.is_null() {
                        return None;
                    }
                    let ctx = XPathContext { pointer: ctx_ptr };

                    // evaluate the XPointer expression
                    let obj_ptr = unsafe {
                        libxml::bindings::xmlXPtrEval(
                            c_uri.as_ptr() as *const libxml::bindings::xmlChar,
                            ctx.pointer,
                        )
                    };
                    if obj_ptr.is_null() {
                        return None;
                    }
                    let obj = XPathObject { pointer: obj_ptr };

                    // extract the nodeset from the result
                    let obj_type = unsafe { (*obj.pointer).type_ };
                    if obj_type != libxml::bindings::xmlXPathObjectType_XPATH_NODESET {
                        return None;
                    }
                    let obj_nodeset = unsafe { (*obj.pointer).nodesetval };
                    let nodeset_count = unsafe { (*obj_nodeset).nodeNr };

                    // go through the nodes and find them in the document
                    for i in 0..nodeset_count {
                        let node_ptr_ptr =
                            unsafe { (*obj_nodeset).nodeTab.offset(i.try_into().unwrap()) };
                        let node_ptr = unsafe { *node_ptr_ptr };
                        if let Some(node) =
                            get_node_by_ptr(&doc.get_root_element().unwrap(), node_ptr)
                        {
                            return Some(node);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Place the signature-verified attributes ([`ATTRIB_SIGVER`] in the given namespace) on the given
/// element, all its descendants and its whole chain of ancestors (but not necessarily all their
/// descendants).
fn place_signature_verified_attributes(
    root_elem: libxml::tree::Node,
    doc: &libxml::tree::Document,
    ns: &libxml::tree::Namespace,
) {
    let mut ptr_to_required_node: HashMap<usize, libxml::tree::Node> = HashMap::new();
    let mut signature_nodes = find_signature_nodes(&root_elem);
    for sig_node in signature_nodes.drain(..) {
        if let Some(sig_root_node) = get_signed_node(&sig_node, doc) {
            let mut nodes = Vec::new();
            let mut parent = sig_root_node.get_parent();
            nodes.push(sig_root_node);

            // mark all children
            while let Some(node) = nodes.pop() {
                let node_ptr = node.node_ptr() as usize;
                for child in node.get_child_elements() {
                    nodes.push(child);
                }
                ptr_to_required_node.entry(node_ptr).or_insert(node);
            }

            // mark the ancestor chain
            while let Some(p) = parent {
                let p_ptr = p.node_ptr() as usize;
                parent = p.get_parent();
                ptr_to_required_node.entry(p_ptr).or_insert(p);
            }
        }
    }
    drop(root_elem);
    for node in ptr_to_required_node.values_mut() {
        node.set_attribute_ns(ATTRIB_SIGVER, VALUE_SIGVER, ns)
            .unwrap();
    }
}

/// Remove all elements that do not contain a signature-verified attribute ([`ATTRIB_SIGVER`] in
/// the namespace [`XMLNS_SIGVER`]).
fn remove_unverified_elements(node: &mut libxml::tree::Node) {
    // depth-first
    for mut child in node.get_child_elements() {
        remove_unverified_elements(&mut child);
    }

    if node.get_attribute_ns(ATTRIB_SIGVER, XMLNS_SIGVER) != Some(String::from(VALUE_SIGVER)) {
        // element is unverified; remove it
        node.unlink_node();
    }
}

/// Takes an XML document, parses it, verifies all XML digital signatures against the given
/// certificates, and returns a derived version of the document where all elements that are not
/// covered by a digital signature have been removed.
pub(crate) fn reduce_xml_to_signed(
    xml_str: &str,
    certs: &[openssl::x509::X509],
) -> Result<String, XmlSecProviderError> {
    let mut xml = XmlParser::default().parse_string(xml_str)?;
    let mut root_elem = xml.get_root_element().ok_or(XmlSecProviderError::XmlMissingRootElement)?;

    // collect ID attribute values and tell libxml about them
    collect_id_attributes(&mut xml)?;

    // verify each signature
    {
        let mut signature_nodes = find_signature_nodes(&root_elem);
        for sig_node in signature_nodes.drain(..) {
            let mut verified = false;
            for openssl_key in certs {
                let mut sig_ctx = XmlSecSignatureContext::new()?;
                let key_data = openssl_key.to_der()?;
                let key = XmlSecKey::from_memory(&key_data, XmlSecKeyFormat::CertDer)?;
                sig_ctx.insert_key(key);
                verified = sig_ctx.verify_node(&sig_node)?;
                if verified {
                    break;
                }
            }

            if !verified {
                return Err(XmlSecProviderError::InvalidSignature);
            }
        }
    }

    // define the "signature verified" namespace
    let sig_ver_ns = libxml::tree::Namespace::new("sv", XMLNS_SIGVER, &mut root_elem)
        .map_err(|err| XmlSecProviderError::XmlNamespaceDefinitionError { error: err })?;

    // remove all existing "signature verified" attributes
    // (we can't do this before verifying the signatures:
    // they might be contained in the XML document proper and signed)
    remove_signature_verified_attributes(&mut root_elem)?;

    // place the "signature verified" attributes on all elements that are:
    // * signed
    // * a descendant of a signed element
    // * an ancestor of a signed element
    place_signature_verified_attributes(root_elem, &xml, &sig_ver_ns);

    // delete all elements that don't have a "signature verified" attribute
    let mut root_elem = xml.get_root_element().ok_or(XmlSecProviderError::XmlMissingRootElement)?;
    remove_unverified_elements(&mut root_elem);

    // remove all "signature verified" attributes again
    remove_signature_verified_attributes(&mut root_elem)?;

    // serialize XML again
    let reduced_xml_str = xml.to_string();
    Ok(reduced_xml_str)
}


fn decrypt(
    t: Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>, XmlSecProviderError> {
    let mut decrypter = Crypter::new(t, Mode::Decrypt, key, iv)?;
    decrypter.pad(false);
    let mut out = vec![0; data.len() + t.block_size()];

    let count = decrypter.update(data, &mut out)?;
    let rest = decrypter.finalize(&mut out[count..])?;

    out.truncate(count + rest);
    Ok(out)
}

fn decrypt_aead(
    t: Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, XmlSecProviderError> {
    let mut decrypter = Crypter::new(t, Mode::Decrypt, key, iv)?;
    decrypter.pad(false);
    let mut out = vec![0; data.len() + t.block_size()];

    decrypter.aad_update(aad)?;
    let count = decrypter.update(data, &mut out)?;
    decrypter.set_tag(tag)?;
    let rest = decrypter.finalize(&mut out[count..])?;

    out.truncate(count + rest);
    Ok(out)
}


