use super::{CertificateDer, CryptoError, ReduceMode};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

use crate::schema::CipherValue;
use libxml::parser::Parser as XmlParser;
use libxml::parser::XmlParseError;
use libxml::tree::NodeType;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::symm::{Cipher, Crypter, Mode};
use std::ffi::{CStr, CString};
use std::ptr::NonNull;

mod wrapper;
use wrapper::{VerifiedReference, XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext};

const XMLNS_XML_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

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
        error: wrapper::XmlSecError,
    },

    #[error("failed to remove attribute: {}", error)]
    XmlAttributeRemovalError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to preserve namespace declaration: {}", error)]
    XmlNamespaceDeclarationError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("encountered malformed XML ID attribute value: {id}")]
    XmlInvalidIdAttribute { id: String },

    #[error("encountered duplicate XML ID attribute value: {id}")]
    XmlDuplicateIdAttribute { id: String },

    #[error("failed to register XML ID attribute value: {id}")]
    XmlIdRegistrationError { id: String },

    #[error("failed to resolve verified reference URI: {uri}")]
    XmlReferenceResolutionError { uri: String },

    #[error("verified pre-digest fragment could not be matched back to the source document")]
    XmlPredigestFragmentInvalid,

    #[error("OpenSSL error stack: {}", error)]
    OpenSSLError {
        #[from]
        error: ErrorStack,
    },
}

impl From<wrapper::XmlSecError> for CryptoError {
    fn from(value: wrapper::XmlSecError) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifiedSelectionKind {
    WholeNode,
    ChildSequence,
}

#[derive(Debug, Clone)]
struct VerifiedSelection {
    anchor: libxml::tree::Node,
    kind: VerifiedSelectionKind,
    uri: String,
    predigest_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AttributeName {
    local_name: String,
    namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NamespaceDeclaration {
    prefix: String,
    href: String,
}

struct ParsedSelection {
    _document: libxml::tree::Document,
    shell_source: Option<libxml::tree::Node>,
    sequence_nodes: Vec<libxml::tree::Node>,
}

fn signature_uses_allowed_algorithm(
    sig_node: &libxml::tree::Node,
    allowed: &[super::AllowedSignatureAlgorithm],
) -> bool {
    let Some(signed_info) = signed_info_node(sig_node) else {
        return false;
    };
    let Some(signature_algorithm) = signature_method_algorithm(&signed_info) else {
        return false;
    };
    if !allowed
        .iter()
        .any(|allowed_algorithm| allowed_algorithm.signature_uri() == signature_algorithm)
    {
        return false;
    }

    let allowed_digest_algorithms = allowed
        .iter()
        .map(super::AllowedSignatureAlgorithm::digest_uri)
        .collect::<HashSet<_>>();
    let Some(digest_algorithms) = reference_digest_algorithms(&signed_info) else {
        return false;
    };

    digest_algorithms
        .iter()
        .all(|algorithm| allowed_digest_algorithms.contains(algorithm.as_str()))
}

fn signed_info_node(sig_node: &libxml::tree::Node) -> Option<libxml::tree::Node> {
    sig_node
        .get_child_elements()
        .into_iter()
        .find(|child| is_xml_dsig_element(child, "SignedInfo"))
}

fn signature_method_algorithm(signed_info: &libxml::tree::Node) -> Option<String> {
    signed_info
        .get_child_elements()
        .into_iter()
        .find(|child| is_xml_dsig_element(child, "SignatureMethod"))?
        .get_attribute("Algorithm")
}

fn reference_digest_algorithms(signed_info: &libxml::tree::Node) -> Option<Vec<String>> {
    let references = signed_info
        .get_child_elements()
        .into_iter()
        .filter(|child| is_xml_dsig_element(child, "Reference"))
        .collect::<Vec<_>>();
    if references.is_empty() {
        return None;
    }

    references.iter().map(reference_digest_algorithm).collect()
}

fn reference_digest_algorithm(reference: &libxml::tree::Node) -> Option<String> {
    reference
        .get_child_elements()
        .into_iter()
        .find(|child| is_xml_dsig_element(child, "DigestMethod"))?
        .get_attribute("Algorithm")
}

fn is_xml_dsig_element(node: &libxml::tree::Node, expected_name: &str) -> bool {
    node.get_name() == expected_name
        && node
            .get_namespace()
            .map(|namespace| namespace.get_href() == XMLNS_XML_DSIG)
            .unwrap_or(false)
}

pub struct XmlSec;

impl super::CryptoProvider for XmlSec {
    type PrivateKey = PKey<Private>;
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        x509_cert_der: &CertificateDer,
        id_attribute: Option<&str>,
    ) -> Result<(), CryptoError> {
        let parser = XmlParser::default();
        let document = parser.parse_string(xml)?;

        let key = XmlSecKey::from_memory(x509_cert_der.der_data(), XmlSecKeyFormat::CertDer)?;
        let mut context = XmlSecSignatureContext::new()?;
        context.insert_key(key);

        let valid = context.verify_document(&document, id_attribute)?;

        if !valid {
            return Err(CryptoError::InvalidSignature);
        }

        Ok(())
    }

    /// Takes an XML document, parses it, verifies all XML digital signatures against the given
    /// certificates, and returns a derived version of the document where all elements that are not
    /// covered by a digital signature have been removed.
    ///
    /// If `allowed_algorithms` is provided, only those signature algorithms will be accepted.
    /// This provides protection against algorithm substitution attacks.
    fn reduce_xml_to_signed_with_allowed_algorithms(
        xml_str: &str,
        certs_der: &[CertificateDer],
        reduce_mode: ReduceMode,
        allowed_algorithms: Option<&[super::AllowedSignatureAlgorithm]>,
    ) -> Result<String, CryptoError> {
        let mut xml = XmlParser::default().parse_string(xml_str)?;

        // collect ID attribute values and tell libxml about them
        collect_id_attributes(&mut xml)?;

        let signature_nodes = {
            let root_elem = xml
                .get_root_element()
                .ok_or(XmlSecProviderError::XmlMissingRootElement)?;
            find_signature_nodes(&root_elem)
        };
        if signature_nodes.is_empty() {
            return Err(CryptoError::InvalidSignature);
        }

        let mut predigest_results = Vec::new();
        let mut selections = Vec::new();

        for sig_node in &signature_nodes {
            if let Some(allowed) = allowed_algorithms {
                if !signature_uses_allowed_algorithm(sig_node, allowed) {
                    return Err(CryptoError::InvalidSignature);
                }
            }

            let mut verified = false;
            let mut verified_references = Vec::new();

            for key_data in certs_der {
                let mut sig_ctx = XmlSecSignatureContext::new_with_flags(
                    wrapper::XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES,
                )?;

                let key = XmlSecKey::from_memory(key_data.der_data(), XmlSecKeyFormat::CertDer)?;
                sig_ctx.insert_key(key);
                verified = sig_ctx.verify_node(sig_node)?;
                if verified {
                    verified_references = sig_ctx.get_verified_references()?;
                    break;
                }
            }

            if !verified {
                return Err(CryptoError::InvalidSignature);
            }

            for verified_reference in verified_references {
                if reduce_mode == ReduceMode::PreDigest {
                    predigest_results.push(verified_reference.predigest_xml);
                    continue;
                }

                selections.push(build_verified_selection(
                    &xml,
                    sig_node,
                    verified_reference,
                )?);
            }
        }

        if reduce_mode == ReduceMode::PreDigest {
            return predigest_result(predigest_results);
        }

        if selections.is_empty() {
            return Err(CryptoError::InvalidSignature);
        }

        let (nodes_to_keep, allowed_attributes, output_root_ptr) =
            build_keep_state(&xml, &selections, reduce_mode)?;

        drop(selections);
        drop(signature_nodes);

        move_output_root_to_document_root(&mut xml, output_root_ptr)?;

        let mut root_elem = xml
            .get_root_element()
            .ok_or(XmlSecProviderError::XmlMissingRootElement)?;
        prune_unverified_nodes(&mut root_elem, &nodes_to_keep, &allowed_attributes)?;

        Ok(xml.to_string())
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

    fn sign_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        private_key_der: &[u8],
    ) -> Result<String, CryptoError> {
        let parser = XmlParser::default();
        let document = parser.parse_string(xml)?;

        let key = XmlSecKey::from_memory(private_key_der, XmlSecKeyFormat::Der)?;
        let mut context = XmlSecSignatureContext::new()?;
        context.insert_key(key);

        context.sign_document(&document, Some("ID"))?;

        Ok(document.to_string())
    }
}

fn predigest_result(mut predigest_results: Vec<String>) -> Result<String, CryptoError> {
    if predigest_results.len() == 1 {
        return Ok(predigest_results.remove(0));
    }

    let mut response_predigests = predigest_results
        .into_iter()
        .filter(|predigest| predigest_root_is_response(predigest))
        .collect::<Vec<_>>();
    if response_predigests.len() == 1 {
        Ok(response_predigests.remove(0))
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

fn predigest_root_is_response(predigest: &str) -> bool {
    crate::service_provider::root_element_is_saml_protocol_response(predigest)
}

/// Searches the document for all attributes named `ID` and stores them and their values in the XML
/// document's internal ID table.
///
/// This is necessary for signature verification to successfully follow the references from a
/// `<dsig:Signature>` element to the element it has signed.
fn collect_id_attributes(doc: &mut libxml::tree::Document) -> Result<(), XmlSecProviderError> {
    const ID_STR: &str = "ID";
    let id_attr_name = CString::new(ID_STR).unwrap();
    let mut seen_ids = HashSet::new();

    let mut nodes_to_visit = Vec::new();
    if let Some(root_elem) = doc.get_root_element() {
        nodes_to_visit.push(root_elem);
    }
    while let Some(node) = nodes_to_visit.pop() {
        if let Some(id_value) = node.get_attribute(ID_STR) {
            let id_value_cstr = CString::new(id_value.clone()).map_err(|_| {
                XmlSecProviderError::XmlInvalidIdAttribute {
                    id: id_value.clone(),
                }
            })?;
            if !xml_id_value_is_valid(&id_value_cstr) {
                return Err(XmlSecProviderError::XmlInvalidIdAttribute { id: id_value });
            }
            if !seen_ids.insert(id_value.clone()) {
                return Err(XmlSecProviderError::XmlDuplicateIdAttribute { id: id_value });
            }

            let node_ptr = node.node_ptr();
            unsafe {
                let attr =
                    libxml::bindings::xmlHasProp(node_ptr, id_attr_name.as_ptr() as *const u8);
                if attr.is_null()
                    || libxml::bindings::xmlAddID(
                        std::ptr::null_mut(),
                        doc.doc_ptr(),
                        id_value_cstr.as_ptr() as *const u8,
                        attr,
                    )
                    .is_null()
                {
                    return Err(XmlSecProviderError::XmlIdRegistrationError { id: id_value });
                }
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

struct XPathContext {
    pointer: NonNull<libxml::bindings::xmlXPathContext>,
}

impl XPathContext {
    fn new(doc: &libxml::tree::Document, signature_node: &libxml::tree::Node) -> Option<Self> {
        let pointer = unsafe {
            libxml::bindings::xmlXPtrNewContext(
                doc.doc_ptr(),
                signature_node.node_ptr(),
                std::ptr::null_mut(),
            )
        };
        NonNull::new(pointer).map(|pointer| Self { pointer })
    }
}

impl Drop for XPathContext {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeContext(self.pointer.as_ptr()) }
    }
}

struct XPathObject {
    pointer: NonNull<libxml::bindings::xmlXPathObject>,
}

impl XPathObject {
    fn evaluate(context: &XPathContext, xpointer: &CString) -> Option<Self> {
        let pointer = unsafe {
            libxml::bindings::xmlXPtrEval(
                xpointer.as_ptr() as *const libxml::bindings::xmlChar,
                context.pointer.as_ptr(),
            )
        };
        NonNull::new(pointer).map(|pointer| Self { pointer })
    }
}

impl Drop for XPathObject {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeObject(self.pointer.as_ptr()) }
    }
}

fn xml_id_value_is_valid(id_value: &CStr) -> bool {
    unsafe { libxml::bindings::xmlValidateNCName(id_value.as_ptr() as *const u8, 0) == 0 }
}

fn build_verified_selection(
    doc: &libxml::tree::Document,
    signature_node: &libxml::tree::Node,
    verified_reference: VerifiedReference,
) -> Result<VerifiedSelection, CryptoError> {
    let reference_uri = verified_reference.uri.clone().unwrap_or_default();
    let (anchor, _kind) =
        resolve_reference_anchor(verified_reference.uri.as_deref(), doc, signature_node).ok_or(
            XmlSecProviderError::XmlReferenceResolutionError {
                uri: reference_uri.clone(),
            },
        )?;
    let parsed_selection = parse_selection(&anchor, &verified_reference.predigest_xml)?;

    Ok(VerifiedSelection {
        anchor,
        kind: if parsed_selection.shell_source.is_some() {
            VerifiedSelectionKind::WholeNode
        } else {
            VerifiedSelectionKind::ChildSequence
        },
        uri: reference_uri,
        predigest_xml: verified_reference.predigest_xml,
    })
}

fn parse_selection(
    anchor: &libxml::tree::Node,
    predigest_xml: &str,
) -> Result<ParsedSelection, CryptoError> {
    let wrapped_fragment = format!("<samael-fragment>{predigest_xml}</samael-fragment>");
    let fragment_doc = XmlParser::default().parse_string(&wrapped_fragment)?;
    let fragment_root = fragment_doc
        .get_root_element()
        .ok_or(XmlSecProviderError::XmlMissingRootElement)?;
    let fragment_children = supported_fragment_children(&fragment_root);

    if fragment_children.is_empty() {
        return Err(XmlSecProviderError::XmlPredigestFragmentInvalid.into());
    }

    let shell_source = if fragment_children.len() == 1
        && fragment_children[0].is_element_node()
        && anchor.is_element_node()
        && element_identity_matches(anchor, &fragment_children[0])
    {
        Some(fragment_children[0].clone())
    } else {
        None
    };
    let sequence_nodes = if let Some(shell_source) = &shell_source {
        supported_fragment_children(shell_source)
    } else {
        fragment_children
    };

    Ok(ParsedSelection {
        _document: fragment_doc,
        shell_source,
        sequence_nodes,
    })
}

fn build_keep_state(
    doc: &libxml::tree::Document,
    selections: &[VerifiedSelection],
    reduce_mode: ReduceMode,
) -> Result<
    (
        HashSet<usize>,
        HashMap<usize, HashSet<AttributeName>>,
        usize,
    ),
    CryptoError,
> {
    if selections.is_empty() {
        return Err(CryptoError::InvalidSignature);
    }

    let mut nodes_to_keep = HashSet::new();
    let mut allowed_attributes = HashMap::new();

    for selection in selections {
        let parsed_selection = parse_selection(&selection.anchor, &selection.predigest_xml)?;
        let matched = match selection.kind {
            VerifiedSelectionKind::WholeNode => {
                let shell_source = parsed_selection
                    .shell_source
                    .as_ref()
                    .ok_or(XmlSecProviderError::XmlPredigestFragmentInvalid)?;
                collect_matching_node(
                    &selection.anchor,
                    shell_source,
                    &mut nodes_to_keep,
                    &mut allowed_attributes,
                )
            }
            VerifiedSelectionKind::ChildSequence => collect_matching_sequence(
                &supported_fragment_children(&selection.anchor),
                &parsed_selection.sequence_nodes,
                &mut nodes_to_keep,
                &mut allowed_attributes,
            ),
        };

        if !matched {
            return Err(XmlSecProviderError::XmlReferenceResolutionError {
                uri: selection.uri.clone(),
            }
            .into());
        }

        if selection.kind == VerifiedSelectionKind::ChildSequence {
            let anchor_ptr = selection.anchor.node_ptr() as usize;
            nodes_to_keep.insert(anchor_ptr);
            // The anchor shell is retained only to keep the verified child sequence rooted.
            allowed_attributes.entry(anchor_ptr).or_default();
        }
    }

    if nodes_to_keep.is_empty() {
        return Err(XmlSecProviderError::XmlPredigestFragmentInvalid.into());
    }

    let root = doc
        .get_root_element()
        .ok_or(XmlSecProviderError::XmlMissingRootElement)?;
    if reduce_mode == ReduceMode::ValidateAndMark {
        let matched_nodes = nodes_to_keep.clone();
        add_required_ancestors(
            &root,
            &matched_nodes,
            &mut nodes_to_keep,
            &mut allowed_attributes,
        )?;
    }
    let output_root_ptr = determine_output_root_ptr(&root, &nodes_to_keep)?;
    Ok((nodes_to_keep, allowed_attributes, output_root_ptr))
}

fn supported_fragment_children(node: &libxml::tree::Node) -> Vec<libxml::tree::Node> {
    node.get_child_nodes()
        .into_iter()
        .filter(is_supported_fragment_node)
        .collect()
}

fn is_supported_fragment_node(node: &libxml::tree::Node) -> bool {
    matches!(
        node.get_type(),
        Some(
            NodeType::ElementNode
                | NodeType::TextNode
                | NodeType::CDataSectionNode
                | NodeType::CommentNode
                | NodeType::PiNode
        )
    ) && !is_ignorable_text_node(node)
}

fn is_ignorable_text_node(node: &libxml::tree::Node) -> bool {
    node.get_type() == Some(NodeType::TextNode) && node.get_content().trim().is_empty()
}

fn collect_matching_sequence(
    original_children: &[libxml::tree::Node],
    fragment_children: &[libxml::tree::Node],
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) -> bool {
    collect_matching_sequence_from(
        original_children,
        fragment_children,
        0,
        0,
        nodes_to_keep,
        allowed_attributes,
    )
}

fn collect_matching_sequence_from(
    original_children: &[libxml::tree::Node],
    fragment_children: &[libxml::tree::Node],
    original_index: usize,
    fragment_index: usize,
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) -> bool {
    if fragment_index == fragment_children.len() {
        return true;
    }

    for index in original_index..original_children.len() {
        let mut candidate_nodes_to_keep = nodes_to_keep.clone();
        let mut candidate_allowed_attributes = allowed_attributes.clone();

        if collect_matching_node_inner(
            &original_children[index],
            &fragment_children[fragment_index],
            &mut candidate_nodes_to_keep,
            &mut candidate_allowed_attributes,
        ) && collect_matching_sequence_from(
            original_children,
            fragment_children,
            index + 1,
            fragment_index + 1,
            &mut candidate_nodes_to_keep,
            &mut candidate_allowed_attributes,
        ) {
            *nodes_to_keep = candidate_nodes_to_keep;
            *allowed_attributes = candidate_allowed_attributes;
            return true;
        }
    }

    false
}

fn collect_matching_node(
    original_node: &libxml::tree::Node,
    fragment_node: &libxml::tree::Node,
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) -> bool {
    let mut candidate_nodes_to_keep = nodes_to_keep.clone();
    let mut candidate_allowed_attributes = allowed_attributes.clone();

    if collect_matching_node_inner(
        original_node,
        fragment_node,
        &mut candidate_nodes_to_keep,
        &mut candidate_allowed_attributes,
    ) {
        *nodes_to_keep = candidate_nodes_to_keep;
        *allowed_attributes = candidate_allowed_attributes;
        true
    } else {
        false
    }
}

fn collect_matching_node_inner(
    original_node: &libxml::tree::Node,
    fragment_node: &libxml::tree::Node,
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) -> bool {
    match fragment_node.get_type() {
        Some(NodeType::ElementNode) => {
            if !original_node.is_element_node()
                || !fragment_node_matches_original(fragment_node, original_node)
            {
                return false;
            }

            allowed_attributes
                .entry(original_node.node_ptr() as usize)
                .or_default()
                .extend(node_attribute_names(fragment_node));
            nodes_to_keep.insert(original_node.node_ptr() as usize);

            let fragment_children = supported_fragment_children(fragment_node);
            collect_matching_sequence(
                &supported_fragment_children(original_node),
                &fragment_children,
                nodes_to_keep,
                allowed_attributes,
            )
        }
        Some(NodeType::TextNode | NodeType::CDataSectionNode) => {
            if !matches!(
                original_node.get_type(),
                Some(NodeType::TextNode | NodeType::CDataSectionNode)
            ) || fragment_node.get_content() != original_node.get_content()
            {
                return false;
            }

            nodes_to_keep.insert(original_node.node_ptr() as usize);
            true
        }
        Some(NodeType::CommentNode) => {
            if original_node.get_type() != Some(NodeType::CommentNode)
                || fragment_node.get_content() != original_node.get_content()
            {
                return false;
            }

            nodes_to_keep.insert(original_node.node_ptr() as usize);
            true
        }
        Some(NodeType::PiNode) => {
            if original_node.get_type() != Some(NodeType::PiNode)
                || fragment_node.get_name() != original_node.get_name()
                || fragment_node.get_content() != original_node.get_content()
            {
                return false;
            }

            nodes_to_keep.insert(original_node.node_ptr() as usize);
            true
        }
        _ => false,
    }
}

fn add_required_ancestors(
    root: &libxml::tree::Node,
    matched_nodes: &HashSet<usize>,
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) -> Result<(), CryptoError> {
    for node_ptr in matched_nodes.iter().copied().collect::<Vec<_>>() {
        let node = find_node_by_ptr_in_tree(root, node_ptr as *const _)
            .ok_or(XmlSecProviderError::XmlPredigestFragmentInvalid)?;
        mark_all_element_ancestors(&node, nodes_to_keep, allowed_attributes);
    }

    Ok(())
}

fn mark_all_element_ancestors(
    node: &libxml::tree::Node,
    nodes_to_keep: &mut HashSet<usize>,
    allowed_attributes: &mut HashMap<usize, HashSet<AttributeName>>,
) {
    let mut current = node.get_parent();
    while let Some(parent) = current {
        if parent.is_element_node() {
            let parent_ptr = parent.node_ptr() as usize;
            nodes_to_keep.insert(parent_ptr);
            allowed_attributes.entry(parent_ptr).or_default();
        }
        current = parent.get_parent();
    }
}

fn determine_output_root_ptr(
    root: &libxml::tree::Node,
    nodes_to_keep: &HashSet<usize>,
) -> Result<usize, CryptoError> {
    let mut candidates = Vec::new();
    collect_top_level_kept_elements(root, nodes_to_keep, false, &mut candidates);

    if candidates.len() == 1 {
        Ok(candidates[0])
    } else {
        Err(XmlSecProviderError::XmlPredigestFragmentInvalid.into())
    }
}

fn collect_top_level_kept_elements(
    node: &libxml::tree::Node,
    nodes_to_keep: &HashSet<usize>,
    has_kept_element_ancestor: bool,
    candidates: &mut Vec<usize>,
) {
    if !node.is_element_node() {
        return;
    }

    let is_kept = nodes_to_keep.contains(&(node.node_ptr() as usize));
    if is_kept && !has_kept_element_ancestor {
        candidates.push(node.node_ptr() as usize);
        return;
    }

    for child in node.get_child_elements() {
        collect_top_level_kept_elements(
            &child,
            nodes_to_keep,
            has_kept_element_ancestor || is_kept,
            candidates,
        );
    }
}

fn move_output_root_to_document_root(
    doc: &mut libxml::tree::Document,
    output_root_ptr: usize,
) -> Result<(), CryptoError> {
    let current_root = doc
        .get_root_element()
        .ok_or(XmlSecProviderError::XmlMissingRootElement)?;
    if current_root.node_ptr() as usize == output_root_ptr {
        return Ok(());
    }

    let mut new_root = find_node_by_ptr_in_tree(&current_root, output_root_ptr as *const _)
        .ok_or(XmlSecProviderError::XmlPredigestFragmentInvalid)?;
    let namespaces = in_scope_namespace_declarations(doc, &new_root);
    new_root.unlink();
    preserve_namespace_declarations(&mut new_root, namespaces)?;
    doc.set_root_element(&new_root);
    Ok(())
}

fn in_scope_namespace_declarations(
    doc: &libxml::tree::Document,
    node: &libxml::tree::Node,
) -> Vec<NamespaceDeclaration> {
    node.get_namespaces(doc)
        .into_iter()
        .map(|namespace| NamespaceDeclaration {
            prefix: namespace.get_prefix(),
            href: namespace.get_href(),
        })
        .filter(namespace_declaration_should_be_preserved)
        .collect()
}

fn preserve_namespace_declarations(
    node: &mut libxml::tree::Node,
    namespaces: Vec<NamespaceDeclaration>,
) -> Result<(), CryptoError> {
    let mut declared_prefixes = node
        .get_namespace_declarations()
        .into_iter()
        .map(|namespace| namespace.get_prefix())
        .collect::<HashSet<_>>();

    for namespace in namespaces {
        if !declared_prefixes.insert(namespace.prefix.clone()) {
            continue;
        }

        libxml::tree::Namespace::new(&namespace.prefix, &namespace.href, node)
            .map_err(|error| XmlSecProviderError::XmlNamespaceDeclarationError { error })?;
    }

    Ok(())
}

fn namespace_declaration_should_be_preserved(namespace: &NamespaceDeclaration) -> bool {
    !namespace.href.is_empty() && namespace.prefix != "xml" && namespace.prefix != "xmlns"
}

fn element_identity_matches(left: &libxml::tree::Node, right: &libxml::tree::Node) -> bool {
    element_local_name(left) == element_local_name(right)
        && left.get_namespace().map(|namespace| namespace.get_href())
            == right.get_namespace().map(|namespace| namespace.get_href())
}

fn element_local_name(node: &libxml::tree::Node) -> String {
    node.get_name()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn fragment_node_matches_original(
    fragment_node: &libxml::tree::Node,
    original_node: &libxml::tree::Node,
) -> bool {
    match (
        fragment_node.is_element_node(),
        original_node.is_element_node(),
    ) {
        (true, true) => {
            element_identity_matches(fragment_node, original_node)
                && node_attribute_names(fragment_node)
                    .into_iter()
                    .all(|attribute_name| {
                        get_attribute_value(fragment_node, &attribute_name)
                            == get_attribute_value(original_node, &attribute_name)
                    })
        }
        (false, false) if fragment_node.is_text_node() && original_node.is_text_node() => {
            fragment_node.get_content() == original_node.get_content()
        }
        _ => false,
    }
}

fn node_attribute_names(node: &libxml::tree::Node) -> Vec<AttributeName> {
    let mut attributes = Vec::new();

    unsafe {
        let mut current_attr = first_attribute_ptr(node.node_ptr());
        while !current_attr.is_null() {
            attributes.push(attribute_name_from_ptr(current_attr));
            current_attr = (*current_attr).next;
        }
    }

    attributes
}

fn attribute_name_from_ptr(attr_ptr: *mut libxml::bindings::xmlAttr) -> AttributeName {
    unsafe {
        let local_name = CStr::from_ptr((*attr_ptr).name as *const std::ffi::c_char)
            .to_string_lossy()
            .into_owned();
        let namespace = if (*attr_ptr).ns.is_null() {
            None
        } else {
            let href = (*(*attr_ptr).ns).href;
            if href.is_null() {
                None
            } else {
                Some(
                    CStr::from_ptr(href as *const std::ffi::c_char)
                        .to_string_lossy()
                        .into_owned(),
                )
            }
        };

        AttributeName {
            local_name,
            namespace,
        }
    }
}

fn find_attribute_ptr(
    node_ptr: *mut libxml::bindings::xmlNode,
    attribute_name: &AttributeName,
) -> *mut libxml::bindings::xmlAttr {
    unsafe {
        let mut current_attr = first_attribute_ptr(node_ptr);
        while !current_attr.is_null() {
            if attribute_name_from_ptr(current_attr) == *attribute_name {
                return current_attr;
            }
            current_attr = (*current_attr).next;
        }
    }

    std::ptr::null_mut()
}

fn first_attribute_ptr(node_ptr: *mut libxml::bindings::xmlNode) -> *mut libxml::bindings::xmlAttr {
    if node_ptr.is_null() {
        return std::ptr::null_mut();
    }

    unsafe { (*node_ptr).properties }
}

fn get_attribute_value(
    node: &libxml::tree::Node,
    attribute_name: &AttributeName,
) -> Option<String> {
    let attr_ptr = find_attribute_ptr(node.node_ptr(), attribute_name);
    if attr_ptr.is_null() {
        return None;
    }

    unsafe {
        let value_ptr =
            libxml::bindings::xmlNodeGetContent(attr_ptr as *mut libxml::bindings::xmlNode);
        if value_ptr.is_null() {
            return Some(String::new());
        }

        let value = CStr::from_ptr(value_ptr as *const std::ffi::c_char)
            .to_string_lossy()
            .into_owned();
        libc::free(value_ptr as *mut libc::c_void);
        Some(value)
    }
}

fn remove_attribute(
    node: &mut libxml::tree::Node,
    attribute_name: &AttributeName,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let node_ptr = node.node_ptr_mut().map_err(|error| {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, error))
            as Box<dyn std::error::Error + Send + Sync>
    })?;
    let attr_ptr = find_attribute_ptr(node_ptr, attribute_name);
    if attr_ptr.is_null() {
        return Ok(());
    }

    unsafe {
        let remove_prop_status = libxml::bindings::xmlRemoveProp(attr_ptr);
        if remove_prop_status == 0 {
            Ok(())
        } else {
            Err(From::from(format!(
                "libxml2 failed to remove property with status: {:?}",
                remove_prop_status
            )))
        }
    }
}

fn resolve_reference_anchor(
    uri: Option<&str>,
    doc: &libxml::tree::Document,
    signature_node: &libxml::tree::Node,
) -> Option<(libxml::tree::Node, VerifiedSelectionKind)> {
    match uri {
        None | Some("") => doc
            .get_root_element()
            .map(|root| (root, VerifiedSelectionKind::WholeNode)),
        Some(uri) => {
            let stripped = uri.strip_prefix('#')?;
            if stripped.starts_with("xpointer(") {
                resolve_xpointer_anchor(stripped, doc, signature_node)
            } else {
                resolve_id_to_node(stripped, doc)
                    .map(|node| (node, VerifiedSelectionKind::WholeNode))
            }
        }
    }
}

fn resolve_id_to_node(id: &str, doc: &libxml::tree::Document) -> Option<libxml::tree::Node> {
    let id_cstring = CString::new(id).ok()?;

    unsafe {
        let target_attr_ptr =
            libxml::bindings::xmlGetID(doc.doc_ptr(), id_cstring.as_ptr() as *const u8);
        if target_attr_ptr.is_null() {
            return None;
        }

        let target_node_ptr = (*target_attr_ptr).parent;
        if target_node_ptr.is_null() {
            return None;
        }
        find_node_by_ptr_in_tree(&doc.get_root_element()?, target_node_ptr)
    }
}

fn resolve_xpointer_anchor(
    xpointer: &str,
    doc: &libxml::tree::Document,
    signature_node: &libxml::tree::Node,
) -> Option<(libxml::tree::Node, VerifiedSelectionKind)> {
    let xpointer = CString::new(xpointer).ok()?;
    let document_root = doc.get_root_element()?;
    let context = XPathContext::new(doc, signature_node)?;
    let object = XPathObject::evaluate(&context, &xpointer)?;

    let mut matched_nodes = resolve_xpointer_matched_nodes(&object, &document_root)?;
    if matched_nodes.len() == 1 && matched_nodes[0].is_element_node() {
        return Some((matched_nodes.remove(0), VerifiedSelectionKind::WholeNode));
    }

    lowest_common_ancestor(&matched_nodes)
        .map(|ancestor| (ancestor, VerifiedSelectionKind::ChildSequence))
}

fn resolve_xpointer_matched_nodes(
    object: &XPathObject,
    document_root: &libxml::tree::Node,
) -> Option<Vec<libxml::tree::Node>> {
    let node_ptrs = unsafe {
        let object_ptr = object.pointer.as_ptr();
        if (*object_ptr).type_ != libxml::bindings::xmlXPathObjectType_XPATH_NODESET {
            return None;
        }

        let node_set = (*object_ptr).nodesetval;
        if node_set.is_null() {
            return None;
        }

        let node_count = (*node_set).nodeNr;
        if node_count <= 0 {
            return Some(Vec::new());
        }

        let node_tab = (*node_set).nodeTab;
        if node_tab.is_null() {
            return None;
        }

        std::slice::from_raw_parts(node_tab, usize::try_from(node_count).ok()?).to_vec()
    };

    let mut matched_nodes = Vec::new();
    for node_ptr in node_ptrs {
        if node_ptr.is_null() {
            continue;
        }

        if let Some(node) = find_node_by_ptr_in_tree(document_root, node_ptr) {
            if let Some(element) = nearest_element_ancestor(&node) {
                matched_nodes.push(element);
            }
        }
    }

    Some(matched_nodes)
}

fn find_node_by_ptr_in_tree(
    root: &libxml::tree::Node,
    target_ptr: *const libxml::bindings::xmlNode,
) -> Option<libxml::tree::Node> {
    if root.node_ptr() == target_ptr as *mut _ {
        return Some(root.clone());
    }

    for child in root.get_child_nodes() {
        if let Some(found) = find_node_by_ptr_in_tree(&child, target_ptr) {
            return Some(found);
        }
    }

    None
}

fn nearest_element_ancestor(node: &libxml::tree::Node) -> Option<libxml::tree::Node> {
    if node.is_element_node() {
        return Some(node.clone());
    }

    let mut current = node.get_parent();
    while let Some(parent) = current {
        if parent.is_element_node() {
            return Some(parent);
        }
        current = parent.get_parent();
    }

    None
}

fn lowest_common_ancestor(nodes: &[libxml::tree::Node]) -> Option<libxml::tree::Node> {
    let ancestor_paths = nodes
        .iter()
        .map(|node| {
            let mut path = Vec::new();
            let mut current = Some(node.clone());

            while let Some(current_node) = current {
                if current_node.is_element_node() {
                    path.push(current_node.clone());
                }
                current = current_node.get_parent();
            }

            path.reverse();
            path
        })
        .collect::<Vec<_>>();

    let shortest_path_len = ancestor_paths
        .iter()
        .map(Vec::len)
        .min()
        .unwrap_or_default();
    let mut common_ancestor = None;

    for index in 0..shortest_path_len {
        let candidate = &ancestor_paths[0][index];
        if ancestor_paths
            .iter()
            .all(|path| path[index].node_ptr() == candidate.node_ptr())
        {
            common_ancestor = Some(candidate.clone());
        } else {
            break;
        }
    }

    common_ancestor
}

fn prune_unverified_nodes(
    node: &mut libxml::tree::Node,
    nodes_to_keep: &HashSet<usize>,
    allowed_attributes: &HashMap<usize, HashSet<AttributeName>>,
) -> Result<(), CryptoError> {
    for mut child in node.get_child_nodes() {
        prune_unverified_nodes(&mut child, nodes_to_keep, allowed_attributes)?;
    }

    if !nodes_to_keep.contains(&(node.node_ptr() as usize)) {
        node.unlink_node();
        return Ok(());
    }

    if node.is_element_node() {
        prune_unsigned_attributes(node, allowed_attributes)?;
    }

    Ok(())
}

fn prune_unsigned_attributes(
    node: &mut libxml::tree::Node,
    allowed_attributes: &HashMap<usize, HashSet<AttributeName>>,
) -> Result<(), CryptoError> {
    let Some(allowed_attributes) = allowed_attributes.get(&(node.node_ptr() as usize)) else {
        return Ok(());
    };

    for attribute_name in node_attribute_names(node) {
        if !allowed_attributes.contains(&attribute_name) {
            remove_attribute(node, &attribute_name)
                .map_err(|error| XmlSecProviderError::XmlAttributeRemovalError { error })?;
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reduce_with_selection<F>(xml: &str, reduce_mode: ReduceMode, make_selection: F) -> String
    where
        F: FnOnce(&libxml::tree::Document) -> VerifiedSelection,
    {
        let mut doc = XmlParser::default().parse_string(xml).unwrap();
        let selections = [make_selection(&doc)];
        let (nodes_to_keep, allowed_attributes, output_root_ptr) =
            build_keep_state(&doc, &selections, reduce_mode).unwrap();
        drop(selections);
        move_output_root_to_document_root(&mut doc, output_root_ptr).unwrap();
        let mut root = doc.get_root_element().unwrap();
        prune_unverified_nodes(&mut root, &nodes_to_keep, &allowed_attributes).unwrap();
        doc.to_string()
    }

    #[test]
    fn predigest_result_returns_single_result_without_reclassifying_it() {
        let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;

        assert_eq!(
            predigest_result(vec![assertion.to_string()]).unwrap(),
            assertion
        );
    }

    #[test]
    fn predigest_result_selects_the_only_response_from_multiple_verified_references() {
        let response = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
        let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;

        assert_eq!(
            predigest_result(vec![assertion.to_string(), response.to_string()]).unwrap(),
            response
        );
    }

    #[test]
    fn predigest_result_rejects_multiple_response_predigests() {
        let first_response =
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="first"/>"#;
        let second_response =
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="second"/>"#;

        assert!(matches!(
            predigest_result(vec![
                first_response.to_string(),
                second_response.to_string()
            ]),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn predigest_result_rejects_wrong_namespace_response_from_multiple_verified_references() {
        let wrong_namespace_response = r#"<evil:Response xmlns:evil="urn:example:evil"/>"#;
        let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;

        assert!(matches!(
            predigest_result(vec![
                assertion.to_string(),
                wrong_namespace_response.to_string()
            ]),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn validate_and_mark_keeps_ancestors_for_signed_assertions() {
        let xml = r#"
<Envelope>
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response">
    <Wrapper>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
      </saml:Assertion>
    </Wrapper>
    <Unsigned>remove-me</Unsigned>
  </samlp:Response>
</Envelope>
"#;

        let reduced = reduce_with_selection(xml, ReduceMode::ValidateAndMark, |doc| {
            let assertion = doc.get_root_element().unwrap().get_child_elements()[0]
                .get_child_elements()[0]
                .get_child_elements()[0]
                .clone();

            VerifiedSelection {
                anchor: assertion,
                kind: VerifiedSelectionKind::WholeNode,
                uri: "#assertion".to_string(),
                predigest_xml: r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
      </saml:Assertion>"#
                    .to_string(),
            }
        });

        assert!(reduced.contains("<saml:Assertion"));
        assert!(reduced.contains("<samlp:Response"));
        assert!(reduced.contains("<Wrapper>"));
    }

    #[test]
    fn validate_and_mark_no_ancestors_roots_signed_assertions_at_the_assertion() {
        let xml = r#"
<Envelope>
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="response">
    <Wrapper>
      <saml:Assertion ID="assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
      </saml:Assertion>
    </Wrapper>
    <Unsigned>remove-me</Unsigned>
  </samlp:Response>
</Envelope>
"#;

        let reduced = reduce_with_selection(xml, ReduceMode::ValidateAndMarkNoAncestors, |doc| {
            let assertion = doc.get_root_element().unwrap().get_child_elements()[0]
                .get_child_elements()[0]
                .get_child_elements()[0]
                .clone();

            VerifiedSelection {
                anchor: assertion,
                kind: VerifiedSelectionKind::WholeNode,
                uri: "#assertion".to_string(),
                predigest_xml: r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
      </saml:Assertion>"#
                    .to_string(),
            }
        });

        assert!(reduced.contains("<saml:Assertion"));
        assert!(reduced.contains("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
        assert!(!reduced.contains("<samlp:Response"));
        assert!(!reduced.contains("<Wrapper>"));
    }

    #[test]
    fn child_sequence_roots_on_the_anchor_shell_and_strips_unsigned_attributes() {
        let xml = r#"
<Response ID="response" Destination="https://evil.example.com/acs">
  <Signed attr="keep" unsigned="drop">value</Signed>
  <Unsigned>remove-me</Unsigned>
</Response>
"#;

        let reduced = reduce_with_selection(xml, ReduceMode::ValidateAndMarkNoAncestors, |doc| {
            VerifiedSelection {
                anchor: doc.get_root_element().unwrap(),
                kind: VerifiedSelectionKind::ChildSequence,
                uri: "".to_string(),
                predigest_xml: r#"<Signed attr="keep">value</Signed>"#.to_string(),
            }
        });

        assert!(reduced.contains("<Response"));
        assert!(!reduced.contains(r#"Destination="https://evil.example.com/acs""#));
        assert!(reduced.contains(r#"<Signed attr="keep">value</Signed>"#));
        assert!(!reduced.contains("unsigned=\"drop\""));
        assert!(!reduced.contains("<Unsigned>"));
    }

    #[test]
    fn child_sequence_supports_comments_pi_and_cdata() {
        let xml = r#"<Root><Parent ID="signed"><!--keep--><?keep instruction?><![CDATA[cdata-value]]><Child attr="signed" unsigned="drop">value</Child>tail<Drop>remove-me</Drop></Parent><Unsigned>remove-me</Unsigned></Root>"#;

        let doc = XmlParser::default().parse_string(xml).unwrap();
        let root = doc.get_root_element().unwrap();
        let parent = root.get_child_elements()[0].clone();
        let parsed = parse_selection(
            &parent,
            "<!--keep--><?keep instruction?>cdata-value<Child attr=\"signed\">value</Child>tail",
        )
        .unwrap();

        let original_children = supported_fragment_children(&parent);
        let mut nodes_to_keep = HashSet::new();
        let mut allowed_attributes = HashMap::new();

        assert!(collect_matching_sequence(
            &original_children,
            &parsed.sequence_nodes,
            &mut nodes_to_keep,
            &mut allowed_attributes,
        ));

        assert_eq!(parsed.sequence_nodes.len(), 5);
        assert!(nodes_to_keep.len() >= 5);
        let child = parent
            .get_child_elements()
            .into_iter()
            .find(|node| node.get_name() == "Child")
            .unwrap();
        let child_attributes = allowed_attributes
            .get(&(child.node_ptr() as usize))
            .expect("matched child should record allowed attributes");

        assert!(child_attributes.contains(&AttributeName {
            local_name: "attr".to_string(),
            namespace: None,
        }));
        assert!(!child_attributes.contains(&AttributeName {
            local_name: "unsigned".to_string(),
            namespace: None,
        }));
    }

    #[test]
    fn attribute_matching_is_namespace_aware() {
        let xml = r#"
<Root xmlns:a="urn:test:a" xmlns:b="urn:test:b">
  <Parent a:id="keep" b:id="drop" plain="keep">value</Parent>
</Root>
"#;

        let doc = XmlParser::default().parse_string(xml).unwrap();
        let mut parent = doc.get_root_element().unwrap().get_child_elements()[0].clone();
        let fragment_doc = XmlParser::default()
            .parse_string(r#"<Root><Parent xmlns:a="urn:test:a" a:id="keep" plain="keep">value</Parent></Root>"#)
            .unwrap();
        let fragment_parent = fragment_doc
            .get_root_element()
            .unwrap()
            .get_child_elements()[0]
            .clone();

        assert!(fragment_node_matches_original(&fragment_parent, &parent));

        let allowed_attributes = HashMap::from([(
            parent.node_ptr() as usize,
            node_attribute_names(&fragment_parent).into_iter().collect(),
        )]);
        prune_unsigned_attributes(&mut parent, &allowed_attributes).unwrap();
        let reduced = doc.to_string();

        assert!(reduced.contains(r#"a:id="keep""#));
        assert!(reduced.contains(r#"plain="keep""#));
        assert!(!reduced.contains(r#"b:id="drop""#));
    }

    #[test]
    fn collect_id_attributes_rejects_non_ncname_values() {
        let mut doc = XmlParser::default()
            .parse_string(r#"<Response><Assertion ID="element(/1/2)"/></Response>"#)
            .unwrap();

        let error = collect_id_attributes(&mut doc).expect_err(
            "non-NCName ID values should be rejected before entering libxml's ID table",
        );

        assert!(matches!(
            error,
            XmlSecProviderError::XmlInvalidIdAttribute { .. }
        ));
    }

    #[test]
    fn collect_id_attributes_rejects_duplicate_values() {
        let mut doc = XmlParser::default()
            .parse_string(r#"<Response><A ID="dup"/><B ID="dup"/></Response>"#)
            .unwrap();

        let error = collect_id_attributes(&mut doc).expect_err("duplicate IDs should fail closed");

        assert!(matches!(
            error,
            XmlSecProviderError::XmlDuplicateIdAttribute { .. }
        ));
    }

    #[test]
    fn resolve_reference_anchor_supports_explicit_xpointer_fragments() {
        let mut doc = XmlParser::default()
            .parse_string(
                r#"<Response ID="response"><Signature/><A ID="a"/><B ID="b"/></Response>"#,
            )
            .unwrap();
        collect_id_attributes(&mut doc).unwrap();

        let root = doc.get_root_element().unwrap();
        let signature_node = root.get_child_elements()[0].clone();
        let (target, kind) =
            resolve_reference_anchor(Some("#xpointer(id('b'))"), &doc, &signature_node).expect(
                "explicit XPointer fragments should resolve through the XPointer evaluator",
            );

        assert_eq!(target.get_name(), "B");
        assert_eq!(kind, VerifiedSelectionKind::WholeNode);
    }

    #[test]
    fn resolve_reference_anchor_rejects_barename_xpointer_lookalikes() {
        let mut doc = XmlParser::default()
            .parse_string(
                r#"<Response ID="response"><Signature/><A ID="a"/><B ID="b"/></Response>"#,
            )
            .unwrap();
        collect_id_attributes(&mut doc).unwrap();

        let root = doc.get_root_element().unwrap();
        let signature_node = root.get_child_elements()[0].clone();
        let target = resolve_reference_anchor(Some("#element(/1/3)"), &doc, &signature_node);
        assert!(
            target.is_none(),
            "barename URI fragments must not be interpreted as XPointer expressions"
        );
    }
}
