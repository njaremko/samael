use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
// use std::convert::TryInto;
#[cfg(feature = "xmlsec")]
use std::ffi::CString;

use std::str::FromStr;
use thiserror::Error;

#[cfg(not(any(feature = "rustcrypto", feature = "openssl")))]
compile_error!("No crypto backend is enabled! Please enable either rustcrypto or openssl.");

#[cfg(all(feature = "rustcrypto", feature = "openssl"))]
compile_error!("Only one crypto backend may be enabled!");

pub mod rsa;
pub mod x509;

#[cfg(feature = "xmlsec")]
use crate::xmlsec::{self, XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext};
#[cfg(feature = "xmlsec")]
use libxml::parser::Parser as XmlParser;

use self::{rsa::PublicKeyLike, x509::CertificateLike};

#[cfg(feature = "xmlsec")]
const XMLNS_XML_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
#[cfg(feature = "xmlsec")]
const XMLNS_SIGVER: &str = "urn:urn-5:08Z8lPlI4JVjifINTfCtfelirUo";
#[cfg(feature = "xmlsec")]
const ATTRIB_SIGVER: &str = "sv";
#[cfg(feature = "xmlsec")]
const VALUE_SIGVER: &str = "verified";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Encountered an invalid signature")]
    InvalidSignature,

    #[error("base64 decoding Error: {}", error)]
    Base64Error {
        #[from]
        error: base64::DecodeError,
    },

    #[error("The given XML is missing a root element")]
    XmlMissingRootElement,

    #[cfg(feature = "xmlsec")]
    #[error("xml sec Error: {}", error)]
    XmlParseError {
        #[from]
        error: libxml::parser::XmlParseError,
    },

    #[cfg(feature = "xmlsec")]
    #[error("xml sec Error: {}", error)]
    XmlSecError {
        #[from]
        error: xmlsec::XmlSecError,
    },

    #[cfg(feature = "xmlsec")]
    #[error("failed to remove attribute: {}", error)]
    XmlAttributeRemovalError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[cfg(feature = "xmlsec")]
    #[error("failed to define namespace: {}", error)]
    XmlNamespaceDefinitionError {
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    #[cfg(all(feature = "xmlsec", feature = "openssl"))]
    #[error("OpenSSL error stack: {}", error)]
    OpenSSLError {
        #[from]
        error: openssl::error::ErrorStack,
    },
}

#[cfg(feature = "xmlsec")]
pub fn sign_xml<Bytes: AsRef<[u8]>>(xml: Bytes, private_key_der: &[u8]) -> Result<String, Error> {
    let parser = XmlParser::default();
    let document = parser.parse_string(xml)?;

    let key = XmlSecKey::from_memory(private_key_der, XmlSecKeyFormat::Der)?;
    let mut context = XmlSecSignatureContext::new()?;
    context.insert_key(key);

    context.sign_document(&document, Some("ID"))?;

    Ok(document.to_string())
}

#[cfg(feature = "xmlsec")]
pub fn verify_signed_xml<Bytes: AsRef<[u8]>>(
    xml: Bytes,
    x509_cert_der: &[u8],
    id_attribute: Option<&str>,
) -> Result<(), Error> {
    let parser = XmlParser::default();
    let document = parser.parse_string(xml)?;

    let key = XmlSecKey::from_memory(x509_cert_der, XmlSecKeyFormat::CertDer)?;
    let mut context = XmlSecSignatureContext::new()?;
    context.insert_key(key);

    let valid = context.verify_document(&document, id_attribute)?;

    if !valid {
        return Err(Error::InvalidSignature);
    }

    Ok(())
}

/// Searches the document for all attributes named `ID` and stores them and their values in the XML
/// document's internal ID table.
///
/// This is necessary for signature verification to successfully follow the references from a
/// `<dsig:Signature>` element to the element it has signed.
#[cfg(feature = "xmlsec")]
fn collect_id_attributes(doc: &mut libxml::tree::Document) -> Result<(), Error> {
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
#[cfg(feature = "xmlsec")]
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
#[cfg(feature = "xmlsec")]
pub fn remove_signature_verified_attributes(node: &mut libxml::tree::Node) -> Result<(), Error> {
    node.remove_attribute_ns(ATTRIB_SIGVER, XMLNS_SIGVER)
        .map_err(|err| Error::XmlAttributeRemovalError { error: err })?;
    for mut child_elem in node.get_child_elements() {
        remove_signature_verified_attributes(&mut child_elem)?;
    }
    Ok(())
}

/// Obtains the first child element of the given node that has the given name and namespace.
#[cfg(feature = "xmlsec")]
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
#[cfg(feature = "xmlsec")]
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

/// Searches for and returns the element with the given value of the `ID` attribute from the subtree
/// rooted at the given node.
#[cfg(feature = "xmlsec")]
fn get_element_by_id(elem: &libxml::tree::Node, id: &str) -> Option<libxml::tree::Node> {
    let mut elems = get_elements_by_predicate(elem, |node| {
        node.get_attribute("ID")
            .map(|node_id| node_id == id)
            .unwrap_or(false)
    });
    let elem = elems.drain(..).next();
    elem
}

/// Searches for and returns the element with the given pointer value from the subtree rooted at the
/// given node.
#[cfg(feature = "xmlsec")]
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

#[cfg(feature = "xmlsec")]
struct XPathContext {
    pub pointer: libxml::bindings::xmlXPathContextPtr,
}
#[cfg(feature = "xmlsec")]
impl Drop for XPathContext {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeContext(self.pointer) }
    }
}

#[cfg(feature = "xmlsec")]
struct XPathObject {
    pub pointer: libxml::bindings::xmlXPathObjectPtr,
}
#[cfg(feature = "xmlsec")]
impl Drop for XPathObject {
    fn drop(&mut self) {
        unsafe { libxml::bindings::xmlXPathFreeObject(self.pointer) }
    }
}

/// Searches for and returns the element at the root of the subtree signed by the given signature
/// node.
#[cfg(feature = "xmlsec")]
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
#[cfg(feature = "xmlsec")]
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
#[cfg(feature = "xmlsec")]
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
#[cfg(feature = "xmlsec")]
pub(crate) fn reduce_xml_to_signed(
    xml_str: &str,
    certs: &Vec<x509::Certificate>,
) -> Result<String, Error> {
    let mut xml = XmlParser::default().parse_string(xml_str)?;
    let mut root_elem = xml.get_root_element().ok_or(Error::XmlMissingRootElement)?;

    // collect ID attribute values and tell libxml about them
    collect_id_attributes(&mut xml)?;

    // verify each signature
    {
        let mut signature_nodes = find_signature_nodes(&root_elem);
        for sig_node in signature_nodes.drain(..) {
            let mut verified = false;
            for openssl_key in certs {
                let mut sig_ctx = XmlSecSignatureContext::new()?;
                let key_data = openssl_key.public_key();
                let key = XmlSecKey::from_memory(&key_data, XmlSecKeyFormat::CertDer)?;
                sig_ctx.insert_key(key);
                verified = sig_ctx.verify_node(&sig_node)?;
                if verified {
                    break;
                }
            }

            if !verified {
                return Err(Error::InvalidSignature);
            }
        }
    }

    // define the "signature verified" namespace
    let sig_ver_ns = libxml::tree::Namespace::new("sv", XMLNS_SIGVER, &mut root_elem)
        .map_err(|err| Error::XmlNamespaceDefinitionError { error: err })?;

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
    let mut root_elem = xml.get_root_element().ok_or(Error::XmlMissingRootElement)?;
    remove_unverified_elements(&mut root_elem);

    // remove all "signature verified" attributes again
    remove_signature_verified_attributes(&mut root_elem)?;

    // serialize XML again
    let reduced_xml_str = xml.to_string();
    Ok(reduced_xml_str)
}

// Util
// strip out 76-width format and decode base64
pub fn decode_x509_cert(x509_cert: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped = x509_cert
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| !b" \n\t\r\x0b\x0c".contains(b))
        .collect::<Vec<u8>>();

    general_purpose::STANDARD.decode(stripped)
}

// 76-width base64 encoding (MIME)
pub fn mime_encode_x509_cert(x509_cert_der: &[u8]) -> String {
    data_encoding::BASE64_MIME.encode(x509_cert_der)
}

pub fn gen_saml_response_id() -> String {
    format!("id{}", uuid::Uuid::new_v4())
}

pub fn gen_saml_assertion_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
}

#[derive(Debug, PartialEq)]
enum SigAlg {
    Unimplemented,
    RsaSha256,
}

impl FromStr for SigAlg {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(SigAlg::RsaSha256),
            _ => Ok(SigAlg::Unimplemented),
        }
    }
}

#[derive(Debug, Error, Clone)]
pub enum UrlVerifierError {
    #[error("Unimplemented SigAlg: {:?}", sigalg)]
    SigAlgUnimplemented { sigalg: String },
}

pub struct UrlVerifier {
    keypair: rsa::PublicKey,
}

impl UrlVerifier {
    pub fn from_rsa_pem(public_key_pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let keypair =rsa::PublicKey::from_pem(public_key_pem)?;
        Ok(Self { keypair })
    }

    pub fn from_rsa_der(public_key_der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = rsa::PublicKey::from_der(public_key_der)?;
        Ok(Self { keypair })
    }

    pub fn from_x509_cert_pem(public_cert_pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pubkey = x509::Certificate::from_pem(public_cert_pem.as_bytes()).unwrap().public_key();
        let keypair = rsa::PublicKey::from_der(pubkey)?;
        Ok(Self { keypair })
    }

    pub fn from_x509(
        public_cert: &x509::Certificate,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = rsa::PublicKey::from_pem(public_cert.public_key())?;
        Ok(Self { keypair })
    }

    // Signed url should look like:
    //
    //   http://idp.example.com/SSOService.php?SAMLRequest=...&SigAlg=...&Signature=...
    //
    // Only want to verify the percent encoded non-Signature portion:
    //
    //   http://idp.example.com/SSOService.php?SAMLRequest=...&SigAlg=...&Signature=...
    //                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^

    pub fn verify_signed_request_url(
        &self,
        signed_request_url: &url::Url,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.verify_signed_url(
            signed_request_url,
            &["SAMLRequest".into(), "RelayState".into(), "SigAlg".into()],
        )
    }

    pub fn verify_signed_response_url(
        &self,
        signed_response_url: &url::Url,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.verify_signed_url(
            signed_response_url,
            &["SAMLResponse".into(), "RelayState".into(), "SigAlg".into()],
        )
    }

    pub fn verify_percent_encoded_request_uri_string(
        &self,
        percent_encoded_uri_string: &String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // percent encoded URI:
        //   /saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        // convert to a URL, then use verify_request_url
        let signed_request_url: url::Url =
            format!("http://dummy.fake{}", percent_encoded_uri_string).parse()?;

        self.verify_signed_request_url(&signed_request_url)
    }

    pub fn verify_percent_encoded_response_uri_string(
        &self,
        percent_encoded_uri_string: &String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // percent encoded URI:
        //   /saml?SAMLResponse=..&SigAlg=..&Signature=..
        //
        // convert to a URL, then use verify_response_url
        let signed_response_url: url::Url =
            format!("http://dummy.fake{}", percent_encoded_uri_string).parse()?;

        self.verify_signed_response_url(&signed_response_url)
    }

    fn verify_signed_url(
        &self,
        signed_url: &url::Url,
        query_keys: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Collect query params from URL
        let query_params = signed_url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();

        // Match against implemented SigAlg
        let sig_alg: SigAlg = SigAlg::from_str(&query_params["SigAlg"])?;
        if sig_alg == SigAlg::Unimplemented {
            return Err(Box::new(UrlVerifierError::SigAlgUnimplemented {
                sigalg: query_params["SigAlg"].clone(),
            }));
        }

        // Construct a Url so that percent encoded query can be easily
        // constructed.
        let mut verify_url = url::Url::parse(
            format!(
                "{}://{}",
                signed_url.scheme(),
                signed_url.host_str().unwrap(),
            )
                .as_str(),
        )?;

        // Section 3.4.4.1 of
        // https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf:
        //
        // To construct the signature, a string consisting of the concatenation
        // of the RelayState (if present), SigAlg, and SAMLRequest (or
        // SAMLResponse) query string parameters (each one URL- encoded) is
        // constructed in one of the following ways (ordered as below):
        //
        //   SAMLRequest=value&RelayState=value&SigAlg=value
        //   SAMLResponse=value&RelayState=value&SigAlg=value
        //
        // Order matters!
        for key in query_keys {
            if query_params.contains_key(key) {
                verify_url
                    .query_pairs_mut()
                    .append_pair(key, &query_params[key]);
            }
        }

        let signed_string: String = verify_url.query().unwrap().to_string();
        let signature = general_purpose::STANDARD.decode(&query_params["Signature"])?;

        self.verify_signature(signed_string.as_bytes(), sig_alg, &signature)
    }

    fn verify_signature(
        &self,
        data: &[u8],
        #[allow(unused_variables)]
        sig_alg: SigAlg,
        signature: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.keypair.verify_sha256(signature, data)
    }
}

#[cfg(test)]
mod test {
    use super::UrlVerifier;
    use crate::service_provider::ServiceProvider;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_verify_uri() {
        let private_key = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/private.der"
        ));

        let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_2_metadata.xml"
        ));

        let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
        let max_issue_delay = Utc::now() - response_instant + chrono::Duration::seconds(60);

        let sp = ServiceProvider {
            metadata_url: Some("http://test_accept_signed_with_correct_key.test".into()),
            acs_url: Some("http://sp.example.com/demo1/index.php?acs".into()),
            idp_metadata: idp_metadata_xml.parse().unwrap(),
            max_issue_delay,
            ..Default::default()
        };

        let authn_request = sp
            .make_authentication_request("http://dummy.fake/saml")
            .unwrap();

        let signed_request_url = authn_request
            .signed_redirect("", private_key)
            .unwrap()
            .unwrap();

        // percent encoeded URL:
        //   http://dummy.fake/saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        // percent encoded URI:
        //   /saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        let uri_string: &String = &signed_request_url[url::Position::BeforePath..].to_string();
        assert!(uri_string.starts_with("/saml?SAMLRequest="));

        let url_verifier =
            UrlVerifier::from_x509(&sp.idp_signing_certs().unwrap().unwrap()[0]).unwrap();

        assert!(url_verifier
            .verify_percent_encoded_request_uri_string(uri_string)
            .unwrap(),);
    }
}
