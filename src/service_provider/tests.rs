use crate::metadata::{ContactPerson, ContactType, EntityDescriptor};
use crate::service_provider::ServiceProviderBuilder;

#[test]
fn test_real_world_idp_initiated_login_can_be_validated() {
    let resp = include_str!("../../test_vectors/idp_metadata_realworld.xml");

    let idp_metadata: EntityDescriptor = crate::metadata::de::from_str(&resp).unwrap();

    let pub_key =
        openssl::x509::X509::from_pem(include_bytes!("../../test_vectors/sp_cert.pem")).unwrap();
    let private_key =
        openssl::rsa::Rsa::private_key_from_pem(include_bytes!("../../test_vectors/sp_key.pem"))
            .unwrap();

    let sp = ServiceProviderBuilder::default()
        .entity_id("samael-12344321".to_string())
        .key(private_key)
        .certificate(pub_key)
        .allow_idp_initiated(true)
        .contact_person(ContactPerson {
            sur_name: Some("Bob".to_string()),
            contact_type: Some(ContactType::Technical.value().to_string()),
            ..ContactPerson::default()
        })
        .idp_metadata(idp_metadata)
        .acs_url("https://29ee6d2e.ngrok.io/saml/acs".to_string())
        .slo_url("http://localhost:8080/saml/slo".to_string())
        .build()
        .unwrap();

    let encoded_resp = include_str!("../../test_vectors/idp_initiated_request.txt");
    sp.validate_base64_response(&encoded_resp).unwrap();
}

#[test]
fn test_real_world_expired_signed_idp_initiated_login_fails() {
    let resp = include_str!("../../test_vectors/idp_metadata_realworld.xml");

    let idp_metadata: EntityDescriptor = crate::metadata::de::from_str(&resp).unwrap();

    let pub_key =
        openssl::x509::X509::from_pem(include_bytes!("../../test_vectors/sp_cert.pem")).unwrap();
    let private_key =
        openssl::rsa::Rsa::private_key_from_pem(include_bytes!("../../test_vectors/sp_key.pem"))
            .unwrap();

    let sp = ServiceProviderBuilder::default()
        .entity_id("samael-12344321".to_string())
        .key(private_key)
        .certificate(pub_key)
        .allow_idp_initiated(true)
        .contact_person(ContactPerson {
            sur_name: Some("Bob".to_string()),
            contact_type: Some(ContactType::Technical.value().to_string()),
            ..ContactPerson::default()
        })
        .idp_metadata(idp_metadata)
        .acs_url("https://29ee6d2e.ngrok.io/saml/acs".to_string())
        .slo_url("http://localhost:8080/saml/slo".to_string())
        .build()
        .unwrap();

    let encoded_resp = include_str!("../../test_vectors/idp_initiated_request.txt");
    assert!(sp.parse_base64_response(&encoded_resp, None).is_err());
}
