#![cfg(feature = "xmlsec")]

use super::*;
use chrono::prelude::*;

use crate::crypto::{CertificateDer, Crypto, CryptoProvider, ReduceMode, XmlSec};
use crate::idp::sp_extractor::{RequiredAttribute, SPMetadataExtractor};
use crate::idp::verified_request::UnverifiedAuthnRequest;
use crate::service_provider::ServiceProvider;

fn cert_der_from_pem(pem: &[u8]) -> CertificateDer {
    CertificateDer::from(
        openssl::x509::X509::from_pem(pem)
            .expect("failed to parse test certificate")
            .to_der()
            .expect("failed to encode test certificate"),
    )
}

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
    Crypto::verify_signed_xml(authn_request_xml, &x509cert, Some("ID"))
        .expect("failed to verify authn request");

    let issuer = extractor.issuer().expect("no issuer");
    let acs = extractor.acs().expect("invalid acs");

    assert_eq!(&issuer, "https://sp.example.com");
    assert_eq!(&acs.url, "https://sp.example.com/acs");
}

#[test]
fn test_signed_response() {
    // init our IdP
    let idp = IdentityProvider::from_rsa_private_key_der(include_bytes!(
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
            &idp_cert,
            "testuser@example.com",
            "https://sp.example.com/audience",
            "https://sp.example.com/acs",
            "https://idp.example.com",
            verified.id.as_str(),
            &attrs,
        )
        .expect("failed to created and sign response");

    let out_xml = out_response
        .to_string()
        .expect("failed to serialize response xml");

    Crypto::verify_signed_xml(out_xml.as_bytes(), &idp_cert, Some("ID"))
        .expect("verification failed");
}

#[test]
fn test_signed_response_threads() {
    let verify = move || {
        let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
        let cert_der = include_bytes!("../../test_vectors/sp_cert.der")
            .to_vec()
            .into();
        let unverified =
            UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
        let _ = unverified
            .try_verify_self_signed()
            .expect("failed to verify self signed signature");
        Crypto::verify_signed_xml(authn_request_xml, &cert_der, Some("ID")).expect("failed verify");
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
    let idp = IdentityProvider::from_rsa_private_key_der(include_bytes!(
        "../../test_vectors/idp_private_key.der"
    ))
    .expect("failed to create idp");

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };

    let idp_cert = idp.create_certificate(&params).expect("idp cert error");
    let response = idp
        .sign_authn_response(
            &idp_cert,
            "testuser@example.com",
            "https://sp.example.com/audience",
            "https://sp.example.com/acs",
            "https://idp.example.com",
            "",
            &[],
        )
        .expect("failed to created and sign response");
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
    assert!(matches!(
        err,
        crate::service_provider::Error::FailedToValidateSignature
    ))
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
        err.to_string(),
        crate::service_provider::Error::FailedToValidateSignature.to_string()
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

    let correct_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed.xml",
    ));

    let resp = sp.parse_xml_response(
        correct_cert_signed_response_xml,
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

    let correct_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_2.xml",
    ));

    let _resp = sp
        .parse_xml_response(
            correct_cert_signed_response_xml,
            Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
        )
        .expect("failed to parse response");
}

#[test]
fn test_accept_signed_with_correct_key_idp_3() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_ecdsa_metadata.xml"
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

    let correct_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_ecdsa.xml",
    ));

    let _resp = sp
        .parse_xml_response(
            correct_cert_signed_response_xml,
            Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
        )
        .expect("failed to parse response");
}

#[test]
fn test_malicious_ancestors_not_included() {
    let signed_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/ancestor_attack_signed.xml"
    ));
    let cert = cert_der_from_pem(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_2_metadata_public.pem"
    )));

    for (reduce_mode, should_contain_attacker_url) in [
        (ReduceMode::PreDigest, false),
        (ReduceMode::ValidateAndMark, false),
        (ReduceMode::ValidateAndMarkNoAncestors, false),
    ] {
        let reduced = XmlSec::reduce_xml_to_signed(signed_xml, &[cert.clone()], reduce_mode)
            .expect("reduce_xml_to_signed should succeed");

        assert_eq!(
            reduced.contains("https://attacker.evil.com"),
            should_contain_attacker_url,
            "Attacker URL containment mismatch for {reduce_mode:?}: expected {should_contain_attacker_url}"
        );
    }
}

#[test]
fn test_object_reference_removed() {
    let signed_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/object_attack_response.xml"
    ));
    let cert = cert_der_from_pem(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_2_metadata_public.pem"
    )));

    for (reduce_mode, should_contain_object) in [
        (ReduceMode::PreDigest, false),
        (ReduceMode::ValidateAndMark, false),
        (ReduceMode::ValidateAndMarkNoAncestors, false),
    ] {
        let reduced = XmlSec::reduce_xml_to_signed(signed_xml, &[cert.clone()], reduce_mode)
            .expect("reduce_xml_to_signed should succeed");

        assert_eq!(
            reduced.contains("ds:Object"),
            should_contain_object,
            "Object containment mismatch for {reduce_mode:?}: expected {should_contain_object}"
        );
    }
}

#[test]
fn test_xpointer_attack_fixture_does_not_verify() {
    let signed_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/xpointer_attack_signed.xml"
    ));
    let cert = CertificateDer::from(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/public.der"
        ))
        .to_vec(),
    );

    let error = XmlSec::verify_signed_xml(signed_xml, &cert, Some("ID"))
        .expect_err("xpointer attack fixture should fail signature verification");

    assert!(matches!(
        error,
        crate::crypto::CryptoError::InvalidSignature
    ));
}

#[test]
fn test_xpath_transforms_validated() {
    let signed_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/xpath_transform.xml"
    ));
    let cert = cert_der_from_pem(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_2_metadata_public.pem"
    )));

    for (reduce_mode, should_contain_malicious) in [
        (ReduceMode::PreDigest, false),
        (ReduceMode::ValidateAndMark, false),
        (ReduceMode::ValidateAndMarkNoAncestors, false),
    ] {
        let reduced = XmlSec::reduce_xml_to_signed(signed_xml, &[cert.clone()], reduce_mode)
            .expect("reduce_xml_to_signed should succeed");

        assert_eq!(
            reduced.contains("malicious"),
            should_contain_malicious,
            "Malicious content containment mismatch for {reduce_mode:?}: expected {should_contain_malicious}"
        );
    }
}
