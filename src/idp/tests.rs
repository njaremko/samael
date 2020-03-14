use super::*;
use crate::crypto::verify_signed_xml;
use crate::idp::sp_extractor::{RequiredAttribute, SPMetadataExtractor};
use crate::idp::verified_request::UnverifiedAuthnRequest;

#[test]
fn test_self_signed_authn_request() {
    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    let unverified = UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
    let _ = unverified
        .try_verify_self_signed()
        .expect("failed to verify self signed signature");
}

#[test]
fn test_extract_sp() {
    let sp_metadata = include_str!("../../test_vectors/sp_metadata.xml");
    let extractor = SPMetadataExtractor::try_from_xml(sp_metadata).expect("invalid entity");
    let x509cert = extractor
        .verification_cert()
        .expect("failed to get x509 cert");

    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    verify_signed_xml(authn_request_xml, x509cert.as_slice(), Some("ID"))
        .expect("failed to verify authn request");

    let issuer = extractor.issuer().expect("no issuer");
    let acs = extractor.acs().expect("invalid acs");

    assert_eq!(&issuer, "https://sp.example.com");
    assert_eq!(&acs.url, "https://sp.example.com/acs");
}

#[test]
fn test_signed_response() {
    // init our IdP
    let idp = IdentityProvider::from_private_key_der(include_bytes!(
        "../../test_vectors/idp_private_key.der"
    ))
    .expect("failed to create idp");

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };

    let idp_cert = idp.create_certificate(&params).expect("idp cert error");

    // init an AuthnRequest
    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    let unverified = UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
    let verified = unverified
        .try_verify_self_signed()
        .expect("failed to verify self signed signature");

    // create some attributes:
    let attrs = vec![
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "firstName",
            "",
        ),
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "lastName",
            "",
        ),
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "firstName",
            "",
        ),
    ];

    let attrs = attrs
        .into_iter()
        .map(|attr| ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: attr.1.to_string(),
                format: Some(attr.0.to_string()),
            },
            value: attr.2,
        })
        .collect::<Vec<ResponseAttribute>>();

    // create and sign a response
    let out_response = idp
        .sign_authn_response(
            idp_cert.as_slice(),
            "testuser@example.com",
            "https://sp.example.com/audience",
            "https://sp.example.com/acs",
            "https://idp.example.com",
            &verified.id.as_str(),
            &attrs,
        )
        .expect("failed to created and sign response");

    let out_xml = out_response
        .to_xml()
        .expect("failed to serialize response xml");
    verify_signed_xml(out_xml.as_bytes(), idp_cert.as_slice(), Some("ID"))
        .expect("verification failed");
}

#[test]
fn test_signed_response_threads() {
    let verify = move || {
        let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
        let cert_der = include_bytes!("../../test_vectors/sp_cert.der");
        let unverified =
            UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
        let _ = unverified
            .try_verify_self_signed()
            .expect("failed to verify self signed signature");
        verify_signed_xml(authn_request_xml, cert_der, Some("ID")).expect("failed verify");
    };

    let mut handles = vec![];
    for _ in 0..4 {
        handles.push(std::thread::spawn(|| test_self_signed_authn_request()));
        handles.push(std::thread::spawn(|| test_extract_sp()));
        handles.push(std::thread::spawn(move || verify()));
    }

    handles
        .into_iter()
        .for_each(|h| h.join().expect("failed thread"));
}
