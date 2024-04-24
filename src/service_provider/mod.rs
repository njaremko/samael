use crate::crypto;
use crate::metadata::{Endpoint, IndexedEndpoint, KeyDescriptor, NameIdFormat, SpSsoDescriptor};
use crate::schema::{Assertion, Response};
use crate::traits::ToXml;
use crate::{
    key_info::{KeyInfo, X509Data},
    metadata::{ContactPerson, EncryptionMethod, EntityDescriptor, HTTP_POST_BINDING},
    schema::{AuthnRequest, Issuer, NameIdPolicy},
};
use base64::{engine::general_purpose, Engine as _};
use chrono::prelude::*;
use chrono::Duration;
use flate2::{write::DeflateEncoder, Compression};
use openssl::pkey::Private;
use openssl::{rsa, x509};
use std::fmt::Debug;
use std::io::Write;
use thiserror::Error;
use url::Url;

#[cfg(test)]
mod tests;

#[cfg(feature = "xmlsec")]
use crate::crypto::reduce_xml_to_signed;

#[cfg(not(feature = "xmlsec"))]
fn reduce_xml_to_signed<T>(xml_str: &str, _keys: &Vec<T>) -> Result<String, Error> {
    Ok(String::from(xml_str))
}

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error(
        "SAML response destination does not match SP ACS URL. {:?} != {:?}",
        response_destination,
        sp_acs_url
    )]
    DestinationValidationError {
        response_destination: Option<String>,
        sp_acs_url: Option<String>,
    },
    #[error("SAML Assertion expired at: {}", time)]
    AssertionExpired { time: String },
    #[error(
        "SAML Assertion Issuer does not match IDP entity ID: {:?} != {:?}",
        issuer,
        entity_id
    )]
    AssertionIssuerMismatch {
        issuer: Option<String>,
        entity_id: Option<String>,
    },
    #[error("SAML Assertion Condition expired at: {}", time)]
    AssertionConditionExpired { time: String },
    #[error("SAML Assertion Condition is not valid until: {}", time)]
    AssertionConditionExpiredBefore { time: String },
    #[error(
        "SAML Assertion Condition has unfulfilled AudienceRequirement: {}",
        requirement
    )]
    AssertionConditionAudienceRestrictionFailed { requirement: String },
    #[error(
        "SAML Response 'InResponseTo' does not match any of the possible request IDs: {:?}",
        possible_ids
    )]
    ResponseInResponseToInvalid { possible_ids: Vec<String> },
    #[error(
        "SAML Response Issuer does not match IDP entity ID: {:?} != {:?}",
        issuer,
        entity_id
    )]
    ResponseIssuerMismatch {
        issuer: Option<String>,
        entity_id: Option<String>,
    },
    #[error("SAML Response expired at: {}", time)]
    ResponseExpired { time: String },
    #[error("SAML Response StatusCode is not successful: {}", code)]
    ResponseBadStatusCode { code: String },
    #[error("Encrypted SAML Assertions are not yet supported")]
    EncryptedAssertionsNotYetSupported,
    #[error("SAML Response and all assertions must be signed")]
    FailedToValidateSignature,
    #[error("Failed to deserialize SAML response.")]
    DeserializeResponseError,
    #[error("Failed to parse cert '{}'. Assumed DER format.", cert)]
    FailedToParseCert { cert: String },
    #[error("Unexpected Error Occurred!")]
    UnexpectedError,

    #[error("Failed to parse SAMLResponse")]
    FailedToParseSamlResponse,

    #[error("ACS url is missing")]
    MissingAcsUrl,

    #[error("SLO url is missing")]
    MissingSloUrl,
}

#[derive(Builder, Clone)]
#[builder(default, setter(into))]
pub struct ServiceProvider {
    pub entity_id: Option<String>,
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
            entity_id: None,
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

        let valid_until = valid_duration.map(|d| Utc::now() + d);

        let entity_id = if let Some(entity_id) = self.entity_id.clone() {
            Some(entity_id)
        } else {
            self.metadata_url.clone()
        };

        let mut key_descriptors = vec![];
        if let Some(cert) = &self.certificate {
            let mut cert_bytes: Vec<u8> = cert.to_der()?;
            if let Some(intermediates) = &self.intermediates {
                for intermediate in intermediates {
                    cert_bytes.append(&mut intermediate.to_der()?);
                }
            }
            key_descriptors.push(KeyDescriptor {
                encryption_methods: None,
                key_use: Some("signing".to_string()),
                key_info: KeyInfo {
                    id: None,
                    x509_data: Some(X509Data {
                        certificates: vec![general_purpose::STANDARD.encode(&cert_bytes)],
                    }),
                },
            });
            key_descriptors.push(KeyDescriptor {
                key_use: Some("signing".to_string()),
                key_info: KeyInfo {
                    id: None,
                    x509_data: Some(X509Data {
                        certificates: vec![general_purpose::STANDARD.encode(&cert_bytes)],
                    }),
                },
                encryption_methods: Some(vec![
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
                ]),
            })
        }

        let sso_sp_descriptor = SpSsoDescriptor {
            protocol_support_enumeration: Some("urn:oasis:names:tc:SAML:2.0:protocol".to_string()),
            key_descriptors: Some(key_descriptors),
            valid_until,
            single_logout_services: Some(vec![Endpoint {
                binding: HTTP_POST_BINDING.to_string(),
                location: self.slo_url.clone().ok_or(Error::MissingSloUrl)?,
                response_location: self.slo_url.clone(),
            }]),
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
            entity_id,
            valid_until,
            sp_sso_descriptors: Some(vec![sso_sp_descriptor]),
            contact_person: self
                .contact_person
                .as_ref()
                .map(|contact_person| vec![contact_person.clone()]),
            ..EntityDescriptor::default()
        })
    }

    fn name_id_format(&self) -> Option<String> {
        self.authn_name_id_format
            .clone()
            .and_then(|v| -> Option<String> {
                if v.is_empty() {
                    Some(NameIdFormat::TransientNameIDFormat.value().to_string())
                } else {
                    Some(v)
                }
            })
    }

    pub fn sso_binding_location(&self, binding: &str) -> Option<String> {
        if let Some(idp_sso_descriptors) = &self.idp_metadata.idp_sso_descriptors {
            for idp_sso_descriptor in idp_sso_descriptors {
                for sso_service in &idp_sso_descriptor.single_sign_on_services {
                    if sso_service.binding == binding {
                        return Some(sso_service.location.clone());
                    }
                }
            }
        }
        None
    }

    pub fn slo_binding_location(&self, binding: &str) -> Option<String> {
        if let Some(idp_sso_descriptors) = &self.idp_metadata.idp_sso_descriptors {
            for idp_sso_descriptor in idp_sso_descriptors {
                for single_logout_services in &idp_sso_descriptor.single_logout_services {
                    if single_logout_services.binding == binding {
                        return Some(single_logout_services.location.clone());
                    }
                }
            }
        }
        None
    }

    pub fn idp_signing_certs(&self) -> Result<Option<Vec<openssl::x509::X509>>, Error> {
        let mut result = vec![];
        if let Some(idp_sso_descriptors) = &self.idp_metadata.idp_sso_descriptors {
            for idp_sso_descriptor in idp_sso_descriptors {
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
            }
            // No signing keys found, look for keys with no use specified
            if result.is_empty() {
                for idp_sso_descriptor in idp_sso_descriptors {
                    for key_descriptor in &idp_sso_descriptor.key_descriptors {
                        if key_descriptor.key_use.is_none()
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

    pub fn parse_base64_response(
        &self,
        encoded_resp: &str,
        possible_request_ids: Option<&[&str]>,
    ) -> Result<Assertion, Box<dyn std::error::Error>> {
        let bytes = general_purpose::STANDARD.decode(encoded_resp)?;
        let decoded = std::str::from_utf8(&bytes)?;
        let assertion = self.parse_xml_response(decoded, possible_request_ids)?;
        Ok(assertion)
    }

    pub fn parse_xml_response(
        &self,
        response_xml: &str,
        possible_request_ids: Option<&[&str]>,
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
        } else if let (Some(in_response_to), Some(possible_request_ids)) =
            (&response.in_response_to, possible_request_ids)
        {
            for req_id in possible_request_ids {
                if req_id == in_response_to {
                    request_id_valid = true;
                }
            }
        }
        if !request_id_valid {
            return Err(Error::ResponseInResponseToInvalid {
                possible_ids: possible_request_ids
                    .into_iter()
                    .flatten()
                    .map(|e| e.to_string())
                    .collect(),
            });
        }
        if response.issue_instant + self.max_issue_delay < Utc::now() {
            return Err(Error::ResponseExpired {
                time: (response.issue_instant + self.max_issue_delay)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            });
        }
        if let Some(issuer) = &response.issuer {
            if issuer.value != self.idp_metadata.entity_id {
                return Err(Error::ResponseIssuerMismatch {
                    issuer: issuer.value.clone(),
                    entity_id: self.idp_metadata.entity_id.clone(),
                });
            }
        }
        if let Some(status) = &response.status {
            if let Some(status) = &status.status_code.value {
                if status != "urn:oasis:names:tc:SAML:2.0:status:Success" {
                    return Err(Error::ResponseBadStatusCode {
                        code: status.clone(),
                    });
                }
            }
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

    fn validate_assertion(
        &self,
        assertion: &Assertion,
        _possible_request_ids: Option<&[&str]>,
    ) -> Result<(), Error> {
        if assertion.issue_instant + self.max_issue_delay < Utc::now() {
            return Err(Error::AssertionExpired {
                time: (assertion.issue_instant + self.max_issue_delay)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            });
        }
        if assertion.issuer.value != self.idp_metadata.entity_id {
            return Err(Error::AssertionIssuerMismatch {
                issuer: assertion.issuer.value.clone(),
                entity_id: self.idp_metadata.entity_id.clone(),
            });
        }
        if let Some(conditions) = &assertion.conditions {
            if let Some(not_before) = conditions.not_before {
                if Utc::now() < not_before - self.max_clock_skew {
                    return Err(Error::AssertionConditionExpiredBefore {
                        time: (not_before - self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                }
            }
            if let Some(not_on_or_after) = conditions.not_on_or_after {
                if not_on_or_after + self.max_clock_skew < Utc::now() {
                    return Err(Error::AssertionConditionExpired {
                        time: (not_on_or_after + self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                }
            }
            if let Some(audience_restrictions) = &conditions.audience_restrictions {
                let mut valid = false;
                if let Some(audience) = self.entity_id.clone().or_else(|| self.metadata_url.clone())
                {
                    for restriction in audience_restrictions {
                        if restriction.audience.iter().any(|a| a == &audience) {
                            valid = true;
                        }
                    }
                    if !valid {
                        return Err(Error::AssertionConditionAudienceRestrictionFailed {
                            requirement: audience,
                        });
                    }
                }
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
        let entity_id = if let Some(entity_id) = self.entity_id.clone() {
            Some(entity_id)
        } else {
            self.metadata_url.clone()
        };

        Ok(AuthnRequest {
            assertion_consumer_service_url: self.acs_url.clone(),
            destination: Some(idp_url.to_string()),
            protocol_binding: Some(HTTP_POST_BINDING.to_string()),
            id: format!("id-{}", rand::random::<u32>()),
            issue_instant: Utc::now(),
            version: "2.0".to_string(),
            issuer: Some(Issuer {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:entity".to_string()),
                value: entity_id,
                ..Issuer::default()
            }),
            name_id_policy: self.name_id_format().map(|format| NameIdPolicy {
                allow_create: Some(true),
                format: Some(format),
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
        let encoded = general_purpose::STANDARD.encode(self.to_xml()?.as_bytes());
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
            encoder.write_all(self.to_xml()?.as_bytes())?;
        }
        let encoded = general_purpose::STANDARD.encode(&compressed_buf);

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

    pub fn signed_redirect(
        &self,
        relay_state: &str,
        private_key_der: &[u8],
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let unsigned_url = self.redirect(relay_state)?;

        if unsigned_url.is_none() {
            return Ok(unsigned_url);
        }

        let mut unsigned_url = unsigned_url.unwrap();

        // Refer to section 3.4.4.1 (page 17) of
        //
        // https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
        //
        // Note: the spec says to remove the Signature related XML elements
        // from the document but leaving them in usually works too.

        // Use rsa-sha256 when signing (see RFC 4051 for choices)
        unsigned_url.query_pairs_mut().append_pair(
            "SigAlg",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        );

        // Sign *only* the existing url's encoded query parameters:
        //
        // http://some.idp.com?SAMLRequest=value&RelayState=value&SigAlg=value
        //                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //
        // then add the "Signature" query parameter afterwards.
        let string_to_sign: String = unsigned_url
            .query()
            .ok_or(Error::UnexpectedError)?
            .to_string();

        // Use openssl's bindings to sign
        let pkey = openssl::rsa::Rsa::private_key_from_der(private_key_der)?;
        let pkey = openssl::pkey::PKey::from_rsa(pkey)?;

        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), pkey.as_ref())?;

        signer.update(string_to_sign.as_bytes())?;

        unsigned_url.query_pairs_mut().append_pair(
            "Signature",
            &general_purpose::STANDARD.encode(signer.sign_to_vec()?),
        );

        // Past this point, it's a signed url :)
        Ok(Some(unsigned_url))
    }
}
