use super::*;
use chrono::prelude::*;

use crate::crypto::verify_signed_xml;
use crate::idp::sp_extractor::{RequiredAttribute, SPMetadataExtractor};
use crate::idp::verified_request::UnverifiedAuthnRequest;
use crate::service_provider::ServiceProvider;

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
    let params = ResponseParams {
        idp_x509_cert_der: idp_cert.as_slice(),
        subject_name_id: "testuser@example.com",
        audience: "https://sp.example.com/audience",
        acs_url: "https://sp.example.com/acs",
        issuer: "https://idp.example.com",
        in_response_to_id: &verified.id.as_str(),
        attributes: &attrs,
        not_before: None,
        not_on_or_after: Some(Utc::now()),
    };

    let out_response = idp.sign_authn_response(&params).expect("failed to created and sign response");

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
        handles.push(std::thread::spawn(test_self_signed_authn_request));
        handles.push(std::thread::spawn(test_extract_sp));
        handles.push(std::thread::spawn(verify));
    }

    handles
        .into_iter()
        .for_each(|h| h.join().expect("failed thread"));
}

#[test]
fn test_signed_response_fingerprint() {
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
    let params = ResponseParams {
        idp_x509_cert_der: idp_cert.as_slice(),
        subject_name_id: "testuser@example.com",
        audience: "https://sp.example.com/audience",
        acs_url: "https://sp.example.com/acs",
        issuer: "https://idp.example.com",
        in_response_to_id: "",
        attributes: &[],
        not_before: None,
        not_on_or_after: Some(Utc::now()),
    };

    let response = idp.sign_authn_response(&params).expect("failed to created and sign response");
    let base64_cert = response
        .signature
        .unwrap()
        .key_info
        .unwrap()
        .first()
        .unwrap()
        .x509_data
        .clone()
        .unwrap()
        .certificates
        .first()
        .cloned()
        .unwrap();
    let der_cert = crate::crypto::decode_x509_cert(&base64_cert).expect("failed to decode cert ");
    assert_eq!(der_cert, idp_cert);
}

#[test]
fn test_do_not_accept_unsigned_response() {
    // If an IdP is configured with signing certs, do not accept unsigned
    // responses.
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
    ));

    let sp = ServiceProvider {
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        ..Default::default()
    };

    // Assert that this descriptor has a signing cert
    assert_eq!(
        sp.idp_metadata.idp_sso_descriptors.as_ref().unwrap()[0].key_descriptors[0]
            .key_use
            .as_ref()
            .unwrap(),
        "signing"
    );
    assert!(
        !sp.idp_metadata.idp_sso_descriptors.as_ref().unwrap()[0].key_descriptors[0]
            .key_info
            .x509_data
            .as_ref()
            .unwrap()
            .certificates
            .first()
            .unwrap()
            .is_empty()
    );

    let unsigned_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response.xml",
    ));

    let resp = sp.parse_xml_response(unsigned_response_xml, None);
    assert!(resp.is_err());

    let err = resp.err().unwrap();
    assert_eq!(
        err,
        crate::service_provider::Error::FailedToParseSamlResponse
    );
}

#[test]
fn test_do_not_accept_signed_with_wrong_key() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
    ));

    let sp = ServiceProvider {
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        ..Default::default()
    };

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_2.xml",
    ));

    let resp = sp.parse_xml_response(wrong_cert_signed_response_xml, None);
    assert!(resp.is_err());

    let err = resp.err().unwrap();

    assert_eq!(
        err,
        crate::service_provider::Error::FailedToValidateSignature
    );
}

#[test]
#[ignore]
fn test_accept_signed_with_correct_key_idp() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
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

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed.xml",
    ));

    let resp = sp.parse_xml_response(
        wrong_cert_signed_response_xml,
        Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
    );

    assert!(resp.is_ok());
}

#[test]
fn test_accept_signed_with_correct_key_idp_2() {
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

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_2.xml",
    ));

    let resp = sp.parse_xml_response(
        wrong_cert_signed_response_xml,
        Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
    );

    assert!(resp.is_ok());
}
