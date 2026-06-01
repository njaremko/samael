#![cfg(feature = "xmlsec")]

#[cfg(test)]
mod encrypted_assertion_tests {
    use crate::crypto::ReduceMode;
    use crate::metadata::EntityDescriptor;
    use crate::schema::{Assertion, Response};
    use crate::service_provider::{Error, ServiceProvider, ServiceProviderBuilder};
    use crate::traits::ToXml;
    use chrono::{DateTime, Duration, Utc};
    use openssl::pkey::PKey;

    fn encrypted_response_max_issue_delay(response_xml: &str) -> Duration {
        let response: Response = response_xml.parse().unwrap();
        Utc::now() - response.issue_instant + Duration::seconds(60)
    }

    fn required_clock_skew_for_not_before(not_before: DateTime<Utc>) -> Duration {
        std::cmp::max(
            not_before - Utc::now() + Duration::seconds(60),
            Duration::zero(),
        )
    }

    fn required_clock_skew_for_not_on_or_after(not_on_or_after: DateTime<Utc>) -> Duration {
        std::cmp::max(
            Utc::now() - not_on_or_after + Duration::seconds(60),
            Duration::zero(),
        )
    }

    fn required_validation_clock_skew(assertion: &Assertion) -> Duration {
        let mut required = Duration::zero();

        if let Some(conditions) = assertion.conditions.as_ref() {
            if let Some(not_before) = conditions.not_before {
                required = std::cmp::max(required, required_clock_skew_for_not_before(not_before));
            }
            if let Some(not_on_or_after) = conditions.not_on_or_after {
                required = std::cmp::max(
                    required,
                    required_clock_skew_for_not_on_or_after(not_on_or_after),
                );
            }
        }

        if let Some(confirmations) = assertion
            .subject
            .as_ref()
            .and_then(|subject| subject.subject_confirmations.as_ref())
        {
            for confirmation in confirmations {
                if let Some(data) = confirmation.subject_confirmation_data.as_ref() {
                    if let Some(not_before) = data.not_before {
                        required =
                            std::cmp::max(required, required_clock_skew_for_not_before(not_before));
                    }
                    if let Some(not_on_or_after) = data.not_on_or_after {
                        required = std::cmp::max(
                            required,
                            required_clock_skew_for_not_on_or_after(not_on_or_after),
                        );
                    }
                }
            }
        }

        required
    }

    fn decrypted_encrypted_response_assertion(
        response_xml: &str,
        key: &PKey<openssl::pkey::Private>,
    ) -> Assertion {
        let response: Response = response_xml.parse().unwrap();
        response
            .encrypted_assertion
            .as_ref()
            .unwrap()
            .decrypt(key)
            .unwrap()
    }

    fn encrypted_response_validation_clock_skew(
        response_xml: &str,
        key: &PKey<openssl::pkey::Private>,
    ) -> Duration {
        let assertion = decrypted_encrypted_response_assertion(response_xml, key);
        required_validation_clock_skew(&assertion)
    }

    fn encrypted_response_entity_id(
        response_xml: &str,
        key: &PKey<openssl::pkey::Private>,
    ) -> String {
        decrypted_encrypted_response_assertion(response_xml, key)
            .conditions
            .as_ref()
            .and_then(|conditions| conditions.audience_restrictions.as_ref())
            .and_then(|restrictions| restrictions.iter().flat_map(|r| r.audience.iter()).next())
            .cloned()
            .unwrap_or_else(|| "example".to_string())
    }

    // Helper function to create a service provider with a private key
    fn create_sp_with_private_key_for_response(
        response_xml: &str,
        key: PKey<openssl::pkey::Private>,
    ) -> ServiceProvider {
        let max_clock_skew = encrypted_response_validation_clock_skew(response_xml, &key);
        let entity_id = encrypted_response_entity_id(response_xml, &key);

        // Create a service provider with the private key
        ServiceProviderBuilder::default()
            .idp_metadata(create_mock_idp())
            .allow_idp_initiated(true)
            .key(key)
            .entity_id(Some(entity_id))
            .max_clock_skew(max_clock_skew)
            .max_issue_delay(encrypted_response_max_issue_delay(response_xml))
            .build()
            .unwrap()
    }

    fn create_sp_with_private_key(key: PKey<openssl::pkey::Private>) -> ServiceProvider {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml"
        ));
        create_sp_with_private_key_for_response(response_xml, key)
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
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml"
        ));

        // Create a service provider without a private key
        let sp = ServiceProviderBuilder::default()
            .idp_metadata(create_mock_idp())
            .max_clock_skew(Duration::days(365))
            .max_issue_delay(encrypted_response_max_issue_delay(response_xml))
            .build()
            .unwrap();

        // Sample response with an encrypted assertion
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

        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted_valid.xml"
        ));
        let sp = create_sp_with_private_key_for_response(response_xml, key);

        let result = sp.parse_xml_response(response_xml, Some(&["example"]));

        assert!(result.is_ok());
    }

    fn extract_first_certificate(xml: &str) -> String {
        let start = xml
            .find("<ds:X509Certificate>")
            .expect("response should contain a signing certificate");
        let start = start + "<ds:X509Certificate>".len();
        let end = xml[start..]
            .find("</ds:X509Certificate>")
            .expect("response should contain a closing certificate tag");
        xml[start..start + end].to_string()
    }

    fn create_predigest_assertion_sp(acs_url: &str) -> ServiceProvider {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let cert = extract_first_certificate(response_xml);
        let metadata_xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://idp.example.com/metadata.php">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        );
        create_predigest_assertion_sp_with_metadata(acs_url, metadata_xml.parse().unwrap())
    }

    fn create_predigest_assertion_sp_without_signing_certs(acs_url: &str) -> ServiceProvider {
        create_predigest_assertion_sp_with_metadata(
            acs_url,
            EntityDescriptor {
                entity_id: Some("http://idp.example.com/metadata.php".to_string()),
                ..Default::default()
            },
        )
    }

    fn create_predigest_assertion_sp_with_metadata(
        acs_url: &str,
        idp_metadata: EntityDescriptor,
    ) -> ServiceProvider {
        let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
        let max_issue_delay = Utc::now() - response_instant + Duration::seconds(60);

        ServiceProviderBuilder::default()
            .idp_metadata(idp_metadata)
            .entity_id(Some("http://sp.example.com/demo1/metadata.php".to_string()))
            .acs_url(Some(acs_url.to_string()))
            .max_clock_skew(Duration::days(5000))
            .max_issue_delay(max_issue_delay)
            .build()
            .unwrap()
    }

    fn refresh_assertion_validation_windows(assertion: &mut Assertion) {
        if let Some(conditions) = assertion.conditions.as_mut() {
            conditions.not_before = Some(Utc::now() - Duration::minutes(1));
            conditions.not_on_or_after = Some(Utc::now() + Duration::days(1));
        }

        if let Some(confirmations) = assertion
            .subject
            .as_mut()
            .and_then(|subject| subject.subject_confirmations.as_mut())
        {
            for confirmation in confirmations {
                if let Some(data) = confirmation.subject_confirmation_data.as_mut() {
                    data.not_before = Some(Utc::now() - Duration::minutes(1));
                    data.not_on_or_after = Some(Utc::now() + Duration::days(1));
                }
            }
        }
    }

    #[test]
    fn test_predigest_accepts_signed_assertion_response() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));

        let assertion = sp
            .parse_xml_response_with_mode(
                response_xml,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
                ReduceMode::PreDigest,
            )
            .expect("signed assertion should parse in pre-digest mode");

        assert_eq!(
            assertion.issuer.value.as_deref(),
            Some("http://idp.example.com/metadata.php")
        );
    }

    #[test]
    fn test_predigest_rejects_mismatched_request_id() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));

        let error = sp
            .parse_xml_response_with_mode(
                response_xml,
                Some(&["WRONG_REQUEST_ID"]),
                ReduceMode::PreDigest,
            )
            .expect_err("mismatched request id should fail in pre-digest mode");

        assert!(matches!(error, Error::AssertionInResponseToInvalid { .. }));
    }

    #[test]
    fn test_predigest_rejects_mismatched_recipient() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?wrong");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));

        let error = sp
            .parse_xml_response_with_mode(
                response_xml,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
                ReduceMode::PreDigest,
            )
            .expect_err("mismatched recipient should fail in pre-digest mode");

        assert!(matches!(error, Error::AssertionRecipientMismatch { .. }));
    }

    #[test]
    fn test_predigest_response_api_rejects_unsigned_bare_assertion_without_signing_certs() {
        let sp = create_predigest_assertion_sp_without_signing_certs(
            "http://sp.example.com/demo1/index.php?acs",
        );
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let response: Response = response_xml.parse().unwrap();
        let assertion_xml = response.assertion.as_ref().unwrap().to_string().unwrap();

        let error = sp
            .parse_xml_response_with_mode(
                &assertion_xml,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
                ReduceMode::PreDigest,
            )
            .expect_err("response parser should not accept a bare unsigned assertion");

        assert!(matches!(error, Error::FailedToParseSamlResponse(_)));
    }

    #[test]
    fn test_default_response_api_ignores_unsigned_response_wrapper_for_signed_assertions() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let mutated_response_xml = response_xml
            .replace(
                r#"Destination="http://sp.example.com/demo1/index.php?acs""#,
                r#"Destination="http://sp.example.com/demo1/index.php?wrong""#,
            )
            .replacen(
                r#"InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685""#,
                r#"InResponseTo="WRONG_REQUEST_ID""#,
                1,
            );

        let assertion = sp
            .parse_xml_response(
                &mutated_response_xml,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect("default response parsing should trust the signed assertion, not the unsigned response wrapper");

        assert_eq!(
            assertion.issuer.value.as_deref(),
            Some("http://idp.example.com/metadata.php")
        );
    }

    // TODO: this should work, but it does not with ValidateAndMark
    #[test]
    fn test_validate_and_mark_only_assertion_signed() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_assertion.xml"
        ));

        let assertion = sp
            .parse_xml_response_with_mode(
                &response_xml,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
                ReduceMode::ValidateAndMark
            )
            .unwrap();

        assert_eq!(
            assertion.issuer.value.as_deref(),
            Some("http://idp.example.com/metadata.php")
        );
    }

    #[test]
    fn test_response_validation_requires_assertion_recipient_binding() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let mut response: Response = response_xml.parse().unwrap();
        response.destination = None;
        response
            .assertion
            .as_mut()
            .unwrap()
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .subject_confirmation_data
            .as_mut()
            .unwrap()
            .recipient = None;

        let error = sp
            .validate_parsed_response(
                response,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect_err("missing bearer recipient should fail response validation");

        assert!(matches!(error, Error::AssertionRecipientMismatch { .. }));
    }

    #[test]
    fn test_validate_assertion_requires_subject_confirmation_expiry() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let response: Response = response_xml.parse().unwrap();
        let mut assertion = response.assertion.unwrap();
        refresh_assertion_validation_windows(&mut assertion);
        assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .subject_confirmation_data
            .as_mut()
            .unwrap()
            .not_on_or_after = None;

        let error = sp
            .validate_assertion(
                &assertion,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect_err("missing subject confirmation expiry should be rejected");

        assert!(matches!(error, Error::AssertionSubjectConfirmationMissing));
    }

    #[test]
    fn test_validate_assertion_requires_bearer_subject_confirmation() {
        let sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let response: Response = response_xml.parse().unwrap();
        let mut assertion = response.assertion.unwrap();
        refresh_assertion_validation_windows(&mut assertion);
        assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .method = Some("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".to_string());

        let error = sp
            .validate_assertion(
                &assertion,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect_err("non-bearer confirmations should be rejected");

        assert!(matches!(
            error,
            Error::AssertionBearerSubjectConfirmationMissing
        ));
    }

    #[test]
    fn test_validate_assertion_rejects_expired_subject_confirmation() {
        let mut sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        sp.max_clock_skew = Duration::zero();

        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let response: Response = response_xml.parse().unwrap();
        let mut assertion = response.assertion.unwrap();
        refresh_assertion_validation_windows(&mut assertion);
        assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .subject_confirmation_data
            .as_mut()
            .unwrap()
            .not_on_or_after = Some(Utc::now() - Duration::minutes(1));

        let error = sp
            .validate_assertion(
                &assertion,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect_err("expired subject confirmation should be rejected");

        assert!(matches!(
            error,
            Error::AssertionSubjectConfirmationExpired { .. }
        ));
    }

    #[test]
    fn test_validate_assertion_rejects_not_yet_valid_subject_confirmation() {
        let mut sp = create_predigest_assertion_sp("http://sp.example.com/demo1/index.php?acs");
        sp.max_clock_skew = Duration::zero();

        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml"
        ));
        let response: Response = response_xml.parse().unwrap();
        let mut assertion = response.assertion.unwrap();
        refresh_assertion_validation_windows(&mut assertion);
        assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .subject_confirmation_data
            .as_mut()
            .unwrap()
            .not_before = Some(Utc::now() + Duration::minutes(1));

        let error = sp
            .validate_assertion(
                &assertion,
                Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
            )
            .expect_err("future subject confirmation should be rejected");

        assert!(matches!(
            error,
            Error::AssertionSubjectConfirmationExpiredBefore { .. }
        ));
    }

    #[test]
    fn test_parse_xml_response_with_empty_saml_response() {
        let mut sp = create_predigest_assertion_sp_with_metadata("https://api.dev.zoo.dev/auth/saml/00000000-00000000-00000000-00000000/login", r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://some.idp.test/blah/">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIB+jCCAWOgAwIBAgIUdcXUPTE+mOSWxRCJh8ldmDMPzREwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEVGVzdDAeFw0yNjA0MDIxMjQzMTNaFw0yNzA0MDIxMjQzMTNaMA8xDTALBgNVBAMMBFRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJEBNDJKH5nXr0hZKcSNIY1l4HeYLPBEKJLXyAnoFTdgGrvi40YyIx9lHh0LbDVWCgxJp21BmKll0CkgmeKidvGlr3FUwtETro44L+SgmjiJNbftvFxhNkgA26O2GDQuBoQwgSiagVadWXwJKkodH8tx4ojBPYK1pBO8fHf3wOnxAgMBAAGjUzBRMB0GA1UdDgQWBBSLoT4AEwcK1+0IMwgo6JYfA4e8ZTAfBgNVHSMEGDAWgBSLoT4AEwcK1+0IMwgo6JYfA4e8ZTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAAtV1hclbZBD17LMbBwyrTj7szmmeUVISPeFEPaAKqiTXrHwRZ+akajboB2JjT3YYMXX2/eDaSvq9f20vJQUvkEAaYu8eNNDKWgm4btJFAeJT8uGxizmTspdJ0cxFSwxqaosV3qIqJgpwLbzUXEcu6mKfyqDM6AeFZdZevkxmKlE</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://some.idp.test/blah/"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://some.idp.test/blah/"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"#.parse().unwrap());
        sp.allow_idp_initiated = true;
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/multi_saml_response_signed_2.xml"
        ));

        let assertion = sp
            .parse_xml_response_with_mode(response_xml, None, ReduceMode::PreDigest)
            .expect("signed assertion should parse in pre-digest mode");
    }
}
