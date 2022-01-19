use crate::crypto;
use crate::metadata::{Endpoint, IndexedEndpoint, KeyDescriptor, NameIdFormat, SpSsoDescriptor};
use crate::schema::{Assertion, NameIdPolicy, Response};
use crate::utils::UtcDateTime;
use crate::{
    key_info::{KeyInfo, X509Data},
    metadata::{ContactPerson, EncryptionMethod, EntityDescriptor, HTTP_POST_BINDING},
    schema::{AuthnRequest, Issuer},
};
use chrono::prelude::*;
use chrono::Duration;
use flate2::{write::DeflateEncoder, Compression};
use openssl::pkey::Private;
use openssl::{rsa, x509};
use snafu::Snafu;
use std::fmt::Debug;
use std::io::Write;
use url::Url;

#[cfg(feature = "xmlsec")]
use crate::crypto::reduce_xml_to_signed;

#[cfg(not(feature = "xmlsec"))]
fn reduce_xml_to_signed<T>(xml_str: &str, _keys: &[T]) -> Result<String, Error> {
    Ok(String::from(xml_str))
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display(
        "SAML response destination does not match SP ACS URL. {:?} != {:?}",
        response_destination,
        sp_acs_url
    ))]
    DestinationValidationError {
        response_destination: Option<String>,
        sp_acs_url: Option<String>,
    },
    #[snafu(display("SAML Assertion expired at: {}", time))]
    AssertionExpired {
        time: String,
    },
    #[snafu(display(
        "SAML Assertion Issuer does not match IDP entity ID: {:?} != {}",
        issuer,
        entity_id
    ))]
    AssertionIssuerMismatch {
        issuer: Option<String>,
        entity_id: String,
    },
    #[snafu(display("SAML Assertion Condition expired at: {}", time))]
    AssertionConditionExpired {
        time: String,
    },
    #[snafu(display("SAML Assertion Condition is not valid until: {}", time))]
    AssertionConditionExpiredBefore {
        time: String,
    },
    #[snafu(display(
        "SAML Assertion Condition has unfulfilled AudienceRequirement: {}",
        requirement
    ))]
    AssertionConditionAudienceRestrictionFailed {
        requirement: String,
    },
    #[snafu(display(
        "SAML Response 'InResponseTo' does not match any of the possible request IDs: {:?}",
        possible_ids
    ))]
    ResponseInResponseToInvalid {
        possible_ids: Vec<String>,
    },
    #[snafu(display(
        "SAML Response Issuer does not match IDP entity ID: {:?} != {}",
        issuer,
        entity_id
    ))]
    ResponseIssuerMismatch {
        issuer: Option<String>,
        entity_id: String,
    },
    #[snafu(display("SAML Response expired at: {}", time))]
    ResponseExpired {
        time: String,
    },
    #[snafu(display("SAML Response StatusCode is not successful: {}", code))]
    ResponseBadStatusCode {
        code: String,
    },
    #[snafu(display("Encrypted SAML Assertions are not yet supported"))]
    EncryptedAssertionsNotYetSupported,
    #[snafu(display("SAML Response and all assertions must be signed"))]
    FailedToValidateSignature,
    #[snafu(display("Failed to deserialize SAML response."))]
    DeserializeResponseError,
    #[snafu(display("Failed to parse cert '{}'. Assumed DER format.", cert))]
    FailedToParseCert {
        cert: String,
    },
    #[snafu(display("Unexpected Error Occurred!"))]
    UnexpectedError,

    #[snafu(display("Failed to parse SAMLResponse"))]
    FailedToParseSamlResponse,

    MissingAcsUrl,
    MissingSloUrl,
}

#[derive(Builder, Clone)]
#[builder(default, setter(into))]
pub struct ServiceProvider {
    pub entity_id: String,
    pub key: Option<rsa::Rsa<Private>>,
    pub certificate: Option<x509::X509>,
    pub intermediates: Option<Vec<x509::X509>>,
    pub metadata_url: Option<String>,
    pub acs_url: Option<String>,
    pub slo_url: Option<String>,
    pub idp_metadata: EntityDescriptor,
    pub authn_name_id_format: Option<String>,
    pub metadata_valid_duration: Option<chrono::Duration>,
    pub force_authn: bool,
    pub allow_idp_initiated: bool,
    pub contact_person: Option<ContactPerson>,
    pub max_issue_delay: Duration,
    pub max_clock_skew: Duration,
}

impl Default for ServiceProvider {
    fn default() -> Self {
        ServiceProvider {
            entity_id: String::from("<unset>"),
            key: None,
            certificate: None,
            intermediates: None,
            metadata_url: Some("http://localhost:8080/saml/metadata".to_string()),
            acs_url: Some("http://localhost:8080/saml/acs".to_string()),
            slo_url: Some("http://localhost:8080/saml/slo".to_string()),
            idp_metadata: EntityDescriptor::default(),
            authn_name_id_format: None,
            metadata_valid_duration: None,
            force_authn: false,
            allow_idp_initiated: false,
            contact_person: None,
            max_issue_delay: Duration::seconds(90),
            max_clock_skew: Duration::seconds(180),
        }
    }
}

impl ServiceProvider {
    pub fn metadata(&self) -> Result<EntityDescriptor, Box<dyn std::error::Error>> {
        let valid_duration = if let Some(duration) = self.metadata_valid_duration {
            Some(duration)
        } else {
            Some(chrono::Duration::hours(48))
        };

        let valid_until = valid_duration.map(|d| UtcDateTime(Utc::now() + d));

        let mut key_descriptors = vec![];
        if let Some(cert) = &self.certificate {
            let mut cert_bytes: Vec<u8> = cert.to_der()?;
            if let Some(intermediates) = &self.intermediates {
                for intermediate in intermediates {
                    cert_bytes.append(&mut intermediate.to_der()?);
                }
            }
            key_descriptors.push(KeyDescriptor {
                encryption_methods: vec![],
                key_use: Some("signing".to_string()),
                key_info: KeyInfo {
                    id: None,
                    x509_data: Some(X509Data {
                        certificates: vec![base64::encode(&cert_bytes)],
                    }),
                },
            });
            key_descriptors.push(KeyDescriptor {
                key_use: Some("signing".to_string()),
                key_info: KeyInfo {
                    id: None,
                    x509_data: Some(X509Data {
                        certificates: vec![base64::encode(&cert_bytes)],
                    }),
                },
                encryption_methods: vec![
                    EncryptionMethod {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc".to_string(),
                    },
                    EncryptionMethod {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc".to_string(),
                    },
                    EncryptionMethod {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc".to_string(),
                    },
                    EncryptionMethod {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".to_string(),
                    },
                ],
            })
        }

        let sso_sp_descriptor = SpSsoDescriptor {
            protocol_support_enumeration: "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            key_descriptors,
            valid_until: valid_until.clone(),
            single_logout_services: vec![Endpoint {
                binding: HTTP_POST_BINDING.to_string(),
                location: self.slo_url.clone().ok_or(Error::MissingSloUrl)?,
                response_location: self.slo_url.clone(),
            }],
            authn_requests_signed: Some(false),
            want_assertions_signed: Some(true),
            assertion_consumer_services: vec![IndexedEndpoint {
                binding: HTTP_POST_BINDING.to_string(),
                location: self.acs_url.clone().ok_or(Error::MissingAcsUrl)?,
                ..IndexedEndpoint::default()
            }],

            ..SpSsoDescriptor::default()
        };

        Ok(EntityDescriptor {
            entity_id: self.entity_id.clone(),
            valid_until,
            sp_sso_descriptors: vec![sso_sp_descriptor],
            contact_person: self.contact_person.clone().into_iter().collect(),
            ..EntityDescriptor::default()
        })
    }

    fn name_id_format(&self) -> Option<String> {
        self.authn_name_id_format
            .clone()
            .and_then(|v| -> Option<String> {
                let unspecified = NameIdFormat::UnspecifiedNameIDFormat.value();
                if v.is_empty() {
                    Some(NameIdFormat::TransientNameIDFormat.value().to_string())
                } else if v == unspecified {
                    None
                } else {
                    Some(v)
                }
            })
    }

    pub fn sso_binding_location(&self, binding: &str) -> Option<String> {
        for idp_sso_descriptor in &self.idp_metadata.idp_sso_descriptors {
            for sso_service in &idp_sso_descriptor.single_sign_on_services {
                if sso_service.binding == binding {
                    return Some(sso_service.location.clone());
                }
            }
        }
        None
    }

    pub fn slo_binding_location(&self, binding: &str) -> Option<String> {
        for idp_sso_descriptor in &self.idp_metadata.idp_sso_descriptors {
            for single_logout_services in &idp_sso_descriptor.single_logout_services {
                if single_logout_services.binding == binding {
                    return Some(single_logout_services.location.clone());
                }
            }
        }
        None
    }

    pub fn idp_signing_certs(&self) -> Result<Option<Vec<openssl::x509::X509>>, Error> {
        let mut result = vec![];
        for idp_sso_descriptor in &self.idp_metadata.idp_sso_descriptors {
            for key_descriptor in &idp_sso_descriptor.key_descriptors {
                if key_descriptor
                    .key_use
                    .as_ref()
                    .filter(|key_use| *key_use == "signing")
                    .is_some()
                {
                    result.append(&mut parse_certificates(key_descriptor)?);
                }
            }
            // No signing keys found, look for keys with no use specified
            if result.is_empty() {
                for idp_sso_descriptor in &self.idp_metadata.idp_sso_descriptors {
                    for key_descriptor in &idp_sso_descriptor.key_descriptors {
                        if key_descriptor.key_use == None
                            || key_descriptor.key_use == Some("".to_string())
                        {
                            result.append(&mut parse_certificates(key_descriptor)?);
                        }
                    }
                }
            }
        }
        Ok(if result.is_empty() {
            None
        } else {
            Some(result)
        })
    }

    pub fn parse_response<AsStr: AsRef<str> + Debug>(
        &self,
        encoded_resp: &str,
        possible_request_ids: &[AsStr],
    ) -> Result<Assertion, Box<dyn std::error::Error>> {
        let bytes = base64::decode(encoded_resp)?;
        let decoded = std::str::from_utf8(&bytes)?;
        let assertion = self.parse_xml_response(decoded, possible_request_ids)?;
        Ok(assertion)
    }

    pub fn parse_xml_response<AsStr: AsRef<str> + Debug>(
        &self,
        response_xml: &str,
        possible_request_ids: &[AsStr],
    ) -> Result<Assertion, Error> {
        let reduced_xml = if let Some(sign_certs) = self.idp_signing_certs()? {
            reduce_xml_to_signed(response_xml, &sign_certs)
                .map_err(|_e| Error::FailedToValidateSignature)?
        } else {
            String::from(response_xml)
        };
        let response: Response = reduced_xml
            .parse()
            .map_err(|_e| Error::FailedToParseSamlResponse)?;
        self.validate_destination(&response)?;
        let mut request_id_valid = false;
        if self.allow_idp_initiated {
            request_id_valid = true;
        } else if let Some(in_response_to) = &response.in_response_to {
            for req_id in possible_request_ids {
                if req_id.as_ref() == in_response_to {
                    request_id_valid = true;
                }
            }
        }
        if !request_id_valid {
            return Err(Error::ResponseInResponseToInvalid {
                possible_ids: possible_request_ids
                    .iter()
                    .map(|e| e.as_ref().to_string())
                    .collect(),
            });
        }
        if response.issue_instant.0 + self.max_issue_delay < Utc::now() {
            return Err(Error::ResponseExpired {
                time: (response.issue_instant.0 + self.max_issue_delay)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            });
        }
        if let Some(issuer) = &response.issuer {
            if issuer.value.as_deref() != Some(&self.idp_metadata.entity_id) {
                return Err(Error::ResponseIssuerMismatch {
                    issuer: issuer.value.clone(),
                    entity_id: self.idp_metadata.entity_id.clone(),
                });
            }
        }
        let status = &response.status.status_code.value;
        if status != "urn:oasis:names:tc:SAML:2.0:status:Success" {
            return Err(Error::ResponseBadStatusCode {
                code: status.clone(),
            });
        }

        if let Some(_encrypted_assertion) = &response.encrypted_assertion {
            Err(Error::EncryptedAssertionsNotYetSupported)
        } else if let Some(assertion) = &response.assertion {
            self.validate_assertion(assertion, possible_request_ids)?;
            Ok(assertion.clone())
        } else {
            Err(Error::UnexpectedError)
        }
    }

    fn validate_assertion<AsStr: AsRef<str> + Debug>(
        &self,
        assertion: &Assertion,
        _possible_request_ids: &[AsStr],
    ) -> Result<(), Error> {
        if assertion.issue_instant.0 + self.max_issue_delay < Utc::now() {
            return Err(Error::AssertionExpired {
                time: (assertion.issue_instant.0 + self.max_issue_delay)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            });
        }
        if assertion.issuer.value.as_deref() != Some(&self.idp_metadata.entity_id) {
            return Err(Error::AssertionIssuerMismatch {
                issuer: assertion.issuer.value.clone(),
                entity_id: self.idp_metadata.entity_id.clone(),
            });
        }
        if let Some(conditions) = &assertion.conditions {
            if let Some(not_before) = &conditions.not_before {
                if Utc::now() < not_before.0 - self.max_clock_skew {
                    return Err(Error::AssertionConditionExpiredBefore {
                        time: (not_before.0 - self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                }
            }
            if let Some(not_on_or_after) = &conditions.not_on_or_after {
                if not_on_or_after.0 + self.max_clock_skew < Utc::now() {
                    return Err(Error::AssertionConditionExpired {
                        time: (not_on_or_after.0 + self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                }
            }
            let mut valid = false;
            for restriction in &conditions.audience_restrictions {
                if restriction.audience.iter().any(|a| a == &self.entity_id) {
                    valid = true;
                }
            }
            if !valid {
                return Err(Error::AssertionConditionAudienceRestrictionFailed {
                    requirement: self.entity_id.clone(),
                });
            }
        }

        Ok(())
    }

    fn validate_destination(&self, response: &Response) -> Result<(), Error> {
        if (response.signature.is_some() || response.destination.is_some())
            && response.destination.as_deref() != self.acs_url.as_deref()
        {
            return Err(Error::DestinationValidationError {
                response_destination: response.destination.clone(),
                sp_acs_url: self.acs_url.clone(),
            });
        }
        Ok(())
    }

    pub fn make_authentication_request(
        &self,
        idp_url: &str,
    ) -> Result<AuthnRequest, Box<dyn std::error::Error>> {
        Ok(AuthnRequest {
            assertion_consumer_service_url: self.acs_url.clone(),
            destination: Some(idp_url.to_string()),
            protocol_binding: Some(HTTP_POST_BINDING.to_string()),
            id: format!("id-{}", rand::random::<u32>()),
            issue_instant: UtcDateTime(Utc::now()),
            version: "2.0".to_string(),
            issuer: Some(Issuer {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:entity".to_string()),
                value: Some(self.entity_id.clone()),
                ..Issuer::default()
            }),
            name_id_policy: Some(NameIdPolicy {
                allow_create: Some(true),
                format: self.name_id_format(),
                ..NameIdPolicy::default()
            }),
            force_authn: Some(self.force_authn),
            ..AuthnRequest::default()
        })
    }
}

fn parse_certificates(key_descriptor: &KeyDescriptor) -> Result<Vec<x509::X509>, Error> {
    key_descriptor
        .key_info
        .x509_data
        .as_ref()
        .map(|data| {
            data.certificates
                .iter()
                .map(|cert| {
                    crypto::decode_x509_cert(cert)
                        .ok()
                        .and_then(|decoded| openssl::x509::X509::from_der(&decoded).ok())
                        .ok_or_else(|| Error::FailedToParseCert {
                            cert: cert.to_string(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or(Ok(vec![]))
}

impl AuthnRequest {
    pub fn post(&self, relay_state: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let encoded = base64::encode(self.as_xml()?.as_bytes());
        if let Some(dest) = &self.destination {
            Ok(Some(format!(
                r#"
            <form method="post" action="{}" id="SAMLRequestForm">
                <input type="hidden" name="SAMLRequest" value="{}" />
                <input type="hidden" name="RelayState" value="{}" />
                <input id="SAMLSubmitButton" type="submit" value="Submit" />
            </form>
            <script>
                document.getElementById('SAMLSubmitButton').style.visibility="hidden";
                document.getElementById('SAMLRequestForm').submit();
            </script>
        "#,
                dest, encoded, relay_state
            )))
        } else {
            Ok(None)
        }
    }

    pub fn redirect(&self, relay_state: &str) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let mut compressed_buf = vec![];
        {
            let mut encoder = DeflateEncoder::new(&mut compressed_buf, Compression::default());
            encoder.write_all(self.as_xml()?.as_bytes())?;
        }
        let encoded = base64::encode(&compressed_buf);

        if let Some(destination) = self.destination.as_ref() {
            let mut url: Url = destination.parse()?;
            url.query_pairs_mut().append_pair("SAMLRequest", &encoded);
            if !relay_state.is_empty() {
                url.query_pairs_mut().append_pair("RelayState", relay_state);
            }
            Ok(Some(url))
        } else {
            Ok(None)
        }
    }
}
