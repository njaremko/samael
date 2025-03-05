#[cfg(test)]
mod encrypted_assertion_tests {
    use crate::metadata::EntityDescriptor;
    use crate::service_provider::{Error, ServiceProvider, ServiceProviderBuilder};
    use chrono::{Duration, Utc};
    use openssl::pkey::PKey;

    // Helper function to create a service provider with a private key
    fn create_sp_with_private_key(key: PKey<openssl::pkey::Private>) -> ServiceProvider {
        // Create a service provider with the private key
        ServiceProviderBuilder::default()
            .idp_metadata(create_mock_idp())
            .allow_idp_initiated(true)
            .key(key)
            .entity_id(Some("example".to_string())) // Set entity_id to match the audience requirement
            .max_clock_skew(Duration::days(365))
            .max_issue_delay(Duration::days(365))
            .build()
            .unwrap()
    }

    fn create_mock_idp() -> EntityDescriptor {
        EntityDescriptor {
            entity_id: Some("saml-mock".to_string()),
            valid_until: Some(Utc::now() + Duration::days(365)),
            ..Default::default()
        }
    }

    #[test]
    fn test_missing_private_key() {
        // Create a service provider without a private key
        let sp = ServiceProviderBuilder::default()
            .idp_metadata(create_mock_idp())
            .max_clock_skew(Duration::days(365))
            .max_issue_delay(Duration::days(365))
            .build()
            .unwrap();

        // Sample response with an encrypted assertion
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml"
        ));

        // Attempt to parse the response
        let result = sp.parse_xml_response(response_xml, Some(&["example"]));

        // Verify that the correct error is returned
        assert_eq!(
            result.err().unwrap().to_string(),
            Error::MissingPrivateKeySP.to_string()
        );
    }

    #[test]
    fn test_decrypt_assertion() {
        // In this test, we're primarily testing the decryption functionality,
        // so we won't perform full validation

        let pkey = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/sp_private.pem"
        ));
        let key = PKey::private_key_from_pem(pkey).unwrap();

        // Create a service provider with the private key but don't validate assertion
        let sp = create_sp_with_private_key(key);

        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml"
        ));

        // Extract encrypted assertion directly to test decryption functionality
        // without validation
        let response: crate::schema::Response = response_xml.parse().unwrap();

        // Verify that an encrypted assertion is present
        assert!(response.encrypted_assertion.is_some());

        // Directly decrypt the assertion without validation
        let result = response
            .encrypted_assertion
            .unwrap()
            .decrypt(&sp.key.unwrap());

        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_and_validate_assertion() {
        let pkey = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/sp_private.pem"
        ));
        let key = PKey::private_key_from_pem(pkey).unwrap();

        let sp = create_sp_with_private_key(key);

        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml"
        ));

        let result = sp.parse_xml_response(response_xml, Some(&["example"]));

        println!("Result: {:?}", result);

        assert!(result.is_ok());
    }
}
