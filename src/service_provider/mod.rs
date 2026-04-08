use crate::crypto;
#[cfg(feature = "xmlsec")]
use crate::crypto::sign_url;
use crate::crypto::{CertificateDer, Crypto, CryptoError, CryptoProvider, ReduceMode};
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
#[cfg(feature = "xmlsec")]
use quick_xml::{
    de::DeError,
    events::{BytesStart, Event as XmlEvent},
    name::ResolveResult,
    NsReader, Writer,
};
use std::fmt::Debug;
use std::io::{Cursor, Write};
use thiserror::Error;
use url::Url;

const SUBJECT_CONFIRMATION_METHOD_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML_STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

#[cfg(test)]
mod tests;

#[cfg(feature = "xmlsec")]
use crate::schema::EncryptedAssertion;

#[derive(Debug, Error)]
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
    #[error("SAML Assertion is missing a bearer SubjectConfirmation")]
    AssertionBearerSubjectConfirmationMissing,
    #[error("SAML Assertion is missing SubjectConfirmationData")]
    AssertionSubjectConfirmationMissing,
    #[error("SAML Assertion SubjectConfirmation expired at: {}", time)]
    AssertionSubjectConfirmationExpired { time: String },
    #[error("SAML Assertion SubjectConfirmation is not valid until: {}", time)]
    AssertionSubjectConfirmationExpiredBefore { time: String },
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
        "SAML Assertion Recipient does not match SP ACS URL. {:?} != {:?}",
        assertion_recipient,
        sp_acs_url
    )]
    AssertionRecipientMismatch {
        assertion_recipient: Option<String>,
        sp_acs_url: Option<String>,
    },
    #[error(
        "SAML Assertion 'InResponseTo' does not match any of the possible request IDs: {:?}",
        possible_ids
    )]
    AssertionInResponseToInvalid { possible_ids: Vec<String> },
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
    #[error("Missing private key on service provider")]
    MissingPrivateKeySP,
    #[error("Missing encrypted key info")]
    MissingEncryptedKeyInfo,
    #[error("Missing encrypted value info")]
    MissingEncryptedValueInfo,
    #[error("Unsupported key encryption method for encrypted assertion: {method}")]
    EncryptedAssertionKeyMethodUnsupported { method: String },
    #[error("Unsupported value encryption method for encrypted assertion: {method}")]
    EncryptedAssertionValueMethodUnsupported { method: String },
    #[error("Encrypted assertion invalid")]
    EncryptedAssertionInvalid,
    #[error("Crypto provider error.")]
    CryptoProviderError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to decrypt assertion")]
    FailedToDecryptAssertion,
    #[error("Tried to use an unsupported key format")]
    UnsupportedKey,

    #[error("Failed to parse SAMLResponse")]
    FailedToParseSamlResponse(#[source] quick_xml::DeError),

    #[error("Failed to parse reduced signed SAML assertion")]
    FailedToParseSamlAssertion(#[source] Box<dyn std::error::Error>),

    #[error("Error parsing the XML in the crypto provider")]
    CryptoXmlError(#[source] CryptoError),

    #[error("ACS url is missing")]
    MissingAcsUrl,

    #[error("SLO url is missing")]
    MissingSloUrl,
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::InvalidSignature
            | CryptoError::Base64Error { .. }
            | CryptoError::XmlMissingRootElement => Error::CryptoXmlError(value),
            CryptoError::CryptoProviderError(error) => Error::CryptoProviderError(error),
            _ => Error::CryptoProviderError(Box::new(value)),
        }
    }
}

#[derive(Builder, Clone)]
#[builder(default, setter(into))]
pub struct ServiceProvider {
    pub entity_id: Option<String>,
    pub key: Option<<Crypto as CryptoProvider>::PrivateKey>,
    pub certificate: Option<CertificateDer>,
    pub intermediates: Option<Vec<CertificateDer>>,
    pub metadata_url: Option<String>,
    pub acs_url: Option<String>,
    pub slo_url: Option<String>,
    pub idp_metadata: EntityDescriptor,
    pub authn_name_id_format: Option<String>,
    pub metadata_valid_duration: Option<Duration>,
    pub force_authn: bool,
    pub allow_idp_initiated: bool,
    pub contact_person: Option<ContactPerson>,
    pub max_issue_delay: Duration,
    pub max_clock_skew: Duration,
    /// Optional list of allowed signature algorithms for signature verification.
    /// If None, all algorithms are allowed (insecure, not recommended).
    /// If Some, only the specified algorithms will be accepted, providing protection
    /// against algorithm substitution attacks.
    pub allowed_signature_algorithms: Option<Vec<crypto::AllowedSignatureAlgorithm>>,
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
            allowed_signature_algorithms: None,
        }
    }
}

impl ServiceProvider {
    pub fn metadata(&self) -> Result<EntityDescriptor, Box<dyn std::error::Error>> {
        let valid_duration = if let Some(duration) = self.metadata_valid_duration {
            Some(duration)
        } else {
            Some(Duration::hours(48))
        };

        let valid_until = valid_duration.map(|d| Utc::now() + d);

        let entity_id = if let Some(entity_id) = self.entity_id.clone() {
            Some(entity_id)
        } else {
            self.metadata_url.clone()
        };

        let mut key_descriptors = vec![];
        if let Some(cert) = &self.certificate {
            let mut cert_bytes: Vec<u8> = cert.der_data().to_vec();
            if let Some(intermediates) = &self.intermediates {
                for intermediate in intermediates {
                    cert_bytes.extend_from_slice(intermediate.der_data());
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
        self.authn_name_id_format.as_ref().map(|v| -> String {
            if v.is_empty() {
                NameIdFormat::TransientNameIDFormat.value().to_string()
            } else {
                v.to_string()
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

    pub fn idp_signing_certs(&self) -> Result<Option<Vec<CertificateDer>>, Error> {
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
        self.parse_base64_response_with_mode(
            encoded_resp,
            possible_request_ids,
            ReduceMode::default(),
        )
    }

    pub fn parse_base64_response_with_mode(
        &self,
        encoded_resp: &str,
        possible_request_ids: Option<&[&str]>,
        reduce_mode: ReduceMode,
    ) -> Result<Assertion, Box<dyn std::error::Error>> {
        let bytes = general_purpose::STANDARD.decode(encoded_resp)?;
        let decoded = std::str::from_utf8(&bytes)?;
        let assertion =
            self.parse_xml_response_with_mode(decoded, possible_request_ids, reduce_mode)?;
        Ok(assertion)
    }

    pub fn parse_xml_response(
        &self,
        response_xml: &str,
        possible_request_ids: Option<&[&str]>,
    ) -> Result<Assertion, Error> {
        self.parse_xml_response_with_mode(response_xml, possible_request_ids, ReduceMode::default())
    }

    pub fn parse_xml_response_with_mode(
        &self,
        response_xml: &str,
        possible_request_ids: Option<&[&str]>,
        reduce_mode: ReduceMode,
    ) -> Result<Assertion, Error> {
        let (reduced_xml, reduced_from_verified_signature) =
            if let Some(sign_certs) = self.idp_signing_certs()? {
                let allowed_algorithms = self.allowed_signature_algorithms.as_deref();

                (
                    Crypto::reduce_xml_to_signed_with_allowed_algorithms(
                        response_xml,
                        &sign_certs,
                        reduce_mode,
                        allowed_algorithms,
                    )
                    .map_err(|_e| Error::FailedToValidateSignature)?,
                    true,
                )
            } else {
                (String::from(response_xml), false)
            };

        match saml_root_element(&reduced_xml)
            .map_err(|error| Error::FailedToParseSamlResponse(DeError::from(error)))?
        {
            Some(SamlRootElement::ProtocolResponse) => match reduced_xml.parse::<Response>() {
                Ok(response) => {
                    return self.validate_parsed_response(response, possible_request_ids);
                }
                Err(_) if reduced_from_verified_signature => {
                    let assertion_xml = verified_assertion_from_response_shell(&reduced_xml)
                        .map_err(Error::FailedToParseSamlAssertion)?;
                    let assertion: Assertion = assertion_xml
                        .parse()
                        .map_err(Error::FailedToParseSamlAssertion)?;
                    self.validate_assertion(&assertion, possible_request_ids)?;
                    return Ok(assertion);
                }
                Err(error) => return Err(Error::FailedToParseSamlResponse(error)),
            },
            Some(SamlRootElement::Assertion) if reduced_from_verified_signature => {
                let assertion: Assertion = reduced_xml
                    .parse()
                    .map_err(Error::FailedToParseSamlAssertion)?;
                self.validate_assertion(&assertion, possible_request_ids)?;
                return Ok(assertion);
            }
            Some(_) => {
                return Err(Error::FailedToParseSamlResponse(DeError::Custom(
                    "unexpected SAML root element".to_string(),
                )));
            }
            None => {}
        }

        let response_parse_error = reduced_xml
            .parse::<Response>()
            .expect_err("non-empty XML without a root element must fail to parse as Response");
        Err(Error::FailedToParseSamlResponse(response_parse_error))
    }

    fn validate_parsed_response(
        &self,
        response: Response,
        possible_request_ids: Option<&[&str]>,
    ) -> Result<Assertion, Error> {
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
            #[cfg(feature = "xmlsec")]
            return self
                .decrypt_assertion(_encrypted_assertion)
                .and_then(|assertion| {
                    self.validate_assertion(&assertion, possible_request_ids)
                        .map(|()| assertion)
                });

            #[cfg(not(feature = "xmlsec"))]
            Err(Error::EncryptedAssertionsNotYetSupported)
        } else if let Some(assertion) = &response.assertion {
            self.validate_assertion(assertion, possible_request_ids)?;
            Ok(assertion.clone())
        } else {
            Err(Error::UnexpectedError)
        }
    }

    #[cfg(feature = "xmlsec")]
    fn decrypt_assertion(
        &self,
        encrypted_assertion: &EncryptedAssertion,
    ) -> Result<Assertion, Error> {
        let key = self.key.as_ref().ok_or(Error::MissingPrivateKeySP)?;

        encrypted_assertion.decrypt(key)
    }

    fn validate_assertion(
        &self,
        assertion: &Assertion,
        possible_request_ids: Option<&[&str]>,
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

        self.validate_assertion_subject_confirmation(assertion, possible_request_ids)?;

        Ok(())
    }

    fn validate_assertion_subject_confirmation(
        &self,
        assertion: &Assertion,
        possible_request_ids: Option<&[&str]>,
    ) -> Result<(), Error> {
        let confirmations = assertion
            .subject
            .as_ref()
            .and_then(|subject| subject.subject_confirmations.as_ref())
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let bearer_confirmations = confirmations
            .iter()
            .filter(|confirmation| {
                confirmation.method.as_deref() == Some(SUBJECT_CONFIRMATION_METHOD_BEARER)
            })
            .collect::<Vec<_>>();

        if bearer_confirmations.is_empty() {
            return Err(Error::AssertionBearerSubjectConfirmationMissing);
        }

        let mut first_error = None;
        for confirmation in bearer_confirmations {
            let Some(data) = confirmation.subject_confirmation_data.as_ref() else {
                first_error.get_or_insert(Error::AssertionSubjectConfirmationMissing);
                continue;
            };

            if let Some(not_before) = data.not_before {
                if Utc::now() < not_before - self.max_clock_skew {
                    first_error.get_or_insert(Error::AssertionSubjectConfirmationExpiredBefore {
                        time: (not_before - self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                    continue;
                }
            }

            if let Some(not_on_or_after) = data.not_on_or_after {
                if not_on_or_after + self.max_clock_skew < Utc::now() {
                    first_error.get_or_insert(Error::AssertionSubjectConfirmationExpired {
                        time: (not_on_or_after + self.max_clock_skew)
                            .to_rfc3339_opts(SecondsFormat::Secs, true),
                    });
                    continue;
                }
            } else {
                first_error.get_or_insert(Error::AssertionSubjectConfirmationMissing);
                continue;
            }

            if data.recipient.as_deref() != self.acs_url.as_deref() {
                first_error.get_or_insert(Error::AssertionRecipientMismatch {
                    assertion_recipient: data.recipient.clone(),
                    sp_acs_url: self.acs_url.clone(),
                });
                continue;
            }

            if self.allow_idp_initiated {
                return Ok(());
            }

            if let Some(possible_request_ids) = possible_request_ids {
                let request_id_valid = data
                    .in_response_to
                    .as_deref()
                    .is_some_and(|id| possible_request_ids.iter().any(|possible| possible == &id));
                if request_id_valid {
                    return Ok(());
                }

                first_error.get_or_insert(Error::AssertionInResponseToInvalid {
                    possible_ids: possible_request_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect(),
                });
                continue;
            }

            first_error.get_or_insert(Error::AssertionInResponseToInvalid {
                possible_ids: Vec::new(),
            });
        }

        Err(first_error.unwrap_or(Error::AssertionSubjectConfirmationMissing))
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SamlRootElement {
    ProtocolResponse,
    Assertion,
    Unsupported,
}

#[cfg(feature = "xmlsec")]
pub(crate) fn root_element_is_saml_protocol_response(xml: &str) -> bool {
    matches!(
        saml_root_element(xml),
        Ok(Some(SamlRootElement::ProtocolResponse))
    )
}

fn saml_root_element(xml: &str) -> quick_xml::Result<Option<SamlRootElement>> {
    let mut reader = NsReader::from_str(xml);

    loop {
        match reader.read_resolved_event()? {
            (namespace, XmlEvent::Start(start)) | (namespace, XmlEvent::Empty(start)) => {
                return Ok(Some(classify_saml_root(
                    &namespace,
                    start.local_name().as_ref(),
                )));
            }
            (_, XmlEvent::Eof) => return Ok(None),
            _ => {}
        }
    }
}

fn classify_saml_root(namespace: &ResolveResult<'_>, local_name: &[u8]) -> SamlRootElement {
    if element_is(namespace, local_name, SAML_PROTOCOL_NS, "Response") {
        SamlRootElement::ProtocolResponse
    } else if element_is(namespace, local_name, SAML_ASSERTION_NS, "Assertion") {
        SamlRootElement::Assertion
    } else {
        SamlRootElement::Unsupported
    }
}

fn verified_assertion_from_response_shell(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = NsReader::from_str(xml);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut namespace_stack = Vec::new();
    let mut root_seen = false;
    let mut response_closed = false;
    let mut depth = 0usize;
    let mut assertion_count = 0usize;
    let mut capture_depth = 0usize;
    let mut status_seen = false;
    let mut status_depth = None;
    let mut status_code_count = 0usize;

    loop {
        let (namespace, event) = reader.read_resolved_event()?;
        match event {
            XmlEvent::Start(start) => {
                if !root_seen {
                    require_response_root(&namespace, start.local_name().as_ref())?;
                    validate_only_namespace_declarations(&start, "Response")?;
                    namespace_stack.push(namespace_declarations(&start)?);
                    root_seen = true;
                    depth = 1;
                    continue;
                }

                reject_content_after_response(response_closed)?;

                if capture_depth > 0 {
                    reject_nested_assertion(&namespace, start.local_name().as_ref())?;
                    namespace_stack.push(namespace_declarations(&start)?);
                    capture_depth += 1;
                    depth += 1;
                    writer.write_event(XmlEvent::Start(start.into_owned()))?;
                    continue;
                }

                if status_depth.is_some() && depth > status_depth.unwrap() {
                    require_status_code(&namespace, start.local_name().as_ref())?;
                    validate_status_code(&start)?;
                    namespace_stack.push(namespace_declarations(&start)?);
                    status_code_count += 1;
                    depth += 1;
                    continue;
                }

                if depth == 1
                    && element_is(
                        &namespace,
                        start.local_name().as_ref(),
                        SAML_ASSERTION_NS,
                        "Assertion",
                    )
                {
                    assertion_count += 1;
                    reject_multiple_assertions(assertion_count)?;
                    namespace_stack.push(namespace_declarations(&start)?);
                    let standalone_start = standalone_assertion_start(start, &namespace_stack)?;
                    writer.write_event(XmlEvent::Start(standalone_start))?;
                    capture_depth = 1;
                    depth += 1;
                } else if depth == 1
                    && element_is(
                        &namespace,
                        start.local_name().as_ref(),
                        SAML_PROTOCOL_NS,
                        "Status",
                    )
                {
                    if status_seen {
                        return reduced_response_shell_error(
                            "reduced signed response shell contains multiple Status elements",
                        );
                    }
                    validate_only_namespace_declarations(&start, "Status")?;
                    namespace_stack.push(namespace_declarations(&start)?);
                    status_seen = true;
                    status_depth = Some(depth);
                    status_code_count = 0;
                    depth += 1;
                } else {
                    reject_unexpected_element(&namespace, start.local_name().as_ref())?;
                }
            }
            XmlEvent::Empty(empty) => {
                if !root_seen {
                    require_response_root(&namespace, empty.local_name().as_ref())?;
                    validate_only_namespace_declarations(&empty, "Response")?;
                    root_seen = true;
                    response_closed = true;
                    continue;
                }

                reject_content_after_response(response_closed)?;

                if capture_depth > 0 {
                    reject_nested_assertion(&namespace, empty.local_name().as_ref())?;
                    writer.write_event(XmlEvent::Empty(empty.into_owned()))?;
                    continue;
                }

                if status_depth.is_some() && depth > status_depth.unwrap() {
                    require_status_code(&namespace, empty.local_name().as_ref())?;
                    validate_status_code(&empty)?;
                    status_code_count += 1;
                    continue;
                }

                if depth == 1
                    && element_is(
                        &namespace,
                        empty.local_name().as_ref(),
                        SAML_ASSERTION_NS,
                        "Assertion",
                    )
                {
                    assertion_count += 1;
                    reject_multiple_assertions(assertion_count)?;
                    namespace_stack.push(namespace_declarations(&empty)?);
                    let standalone_empty = standalone_assertion_start(empty, &namespace_stack)?;
                    namespace_stack.pop();
                    writer.write_event(XmlEvent::Empty(standalone_empty))?;
                } else if depth == 1
                    && element_is(
                        &namespace,
                        empty.local_name().as_ref(),
                        SAML_PROTOCOL_NS,
                        "Status",
                    )
                {
                    return reduced_response_shell_error(
                        "reduced signed response shell Status is missing StatusCode",
                    );
                } else {
                    reject_unexpected_element(&namespace, empty.local_name().as_ref())?;
                }
            }
            XmlEvent::End(end) => {
                let closes_status = status_depth.is_some_and(|open_status_depth| {
                    depth == open_status_depth + 1
                        && element_is(
                            &namespace,
                            end.local_name().as_ref(),
                            SAML_PROTOCOL_NS,
                            "Status",
                        )
                });
                let closes_response = depth == 1
                    && element_is(
                        &namespace,
                        end.local_name().as_ref(),
                        SAML_PROTOCOL_NS,
                        "Response",
                    );

                if capture_depth > 0 {
                    writer.write_event(XmlEvent::End(end.into_owned()))?;
                    capture_depth -= 1;
                }

                if closes_status {
                    if status_code_count == 0 {
                        return reduced_response_shell_error(
                            "reduced signed response shell Status is missing StatusCode",
                        );
                    }
                    status_depth = None;
                }

                if closes_response {
                    response_closed = true;
                }

                if depth == 0 {
                    return reduced_response_shell_error(
                        "reduced signed response shell has an unmatched end element",
                    );
                }
                depth -= 1;
                namespace_stack.pop();
            }
            XmlEvent::Text(text) => {
                if capture_depth > 0 {
                    writer.write_event(XmlEvent::Text(text.into_owned()))?;
                } else if !xml_text_is_whitespace(text.as_ref()) {
                    return reduced_response_shell_error(
                        "reduced signed response shell contains non-whitespace text",
                    );
                }
            }
            XmlEvent::CData(cdata) => {
                if capture_depth > 0 {
                    writer.write_event(XmlEvent::CData(cdata.into_owned()))?;
                } else if !xml_text_is_whitespace(cdata.as_ref()) {
                    return reduced_response_shell_error(
                        "reduced signed response shell contains non-whitespace CDATA",
                    );
                }
            }
            XmlEvent::Comment(comment) => {
                if capture_depth > 0 {
                    writer.write_event(XmlEvent::Comment(comment.into_owned()))?;
                } else {
                    return reduced_response_shell_error(
                        "reduced signed response shell contains an unexpected comment",
                    );
                }
            }
            XmlEvent::Decl(_) if !root_seen => {}
            XmlEvent::Eof => break,
            event => {
                if capture_depth > 0 {
                    writer.write_event(event.into_owned())?;
                } else {
                    return reduced_response_shell_error(
                        "reduced signed response shell contains unexpected XML content",
                    );
                }
            }
        }
    }

    if !root_seen {
        return reduced_response_shell_error(
            "reduced signed response shell is missing Response root",
        );
    }

    if assertion_count != 1 {
        return reduced_response_shell_error(
            "reduced signed response shell must contain exactly one direct SAML assertion",
        );
    }

    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

fn require_response_root(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if element_is(namespace, local_name, SAML_PROTOCOL_NS, "Response") {
        Ok(())
    } else {
        reduced_response_shell_error("reduced signed response shell root is not a SAML Response")
    }
}

fn require_status_code(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if element_is(namespace, local_name, SAML_PROTOCOL_NS, "StatusCode") {
        Ok(())
    } else {
        reduced_response_shell_error(
            "reduced signed response shell Status contains an unexpected element",
        )
    }
}

fn reject_content_after_response(response_closed: bool) -> Result<(), Box<dyn std::error::Error>> {
    if response_closed {
        reduced_response_shell_error(
            "reduced signed response shell contains content after Response",
        )
    } else {
        Ok(())
    }
}

fn reject_multiple_assertions(assertion_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    if assertion_count > 1 {
        reduced_response_shell_error(
            "reduced signed response shell contains multiple direct SAML assertions",
        )
    } else {
        Ok(())
    }
}

fn reject_nested_assertion(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if element_is(namespace, local_name, SAML_ASSERTION_NS, "Assertion") {
        reduced_response_shell_error(
            "reduced signed response shell contains a nested SAML assertion",
        )
    } else {
        Ok(())
    }
}

fn reject_unexpected_element(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if local_name_is(local_name, "Assertion")
        && !element_is(namespace, local_name, SAML_ASSERTION_NS, "Assertion")
    {
        reduced_response_shell_error(
            "reduced signed response shell contains an Assertion outside the SAML assertion namespace",
        )
    } else if local_name_is(local_name, "Status")
        && !element_is(namespace, local_name, SAML_PROTOCOL_NS, "Status")
    {
        reduced_response_shell_error(
            "reduced signed response shell contains a Status outside the SAML protocol namespace",
        )
    } else {
        reduced_response_shell_error(
            "reduced signed response shell contains an unexpected direct child element",
        )
    }
}

fn validate_only_namespace_declarations(
    start: &BytesStart<'_>,
    element_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attribute in start.attributes() {
        let attribute = attribute?;
        if !attribute_is_namespace_declaration(attribute.key.as_ref()) {
            return reduced_response_shell_error(format!(
                "reduced signed response shell {element_name} contains a non-namespace attribute"
            ));
        }
    }

    Ok(())
}

fn validate_status_code(start: &BytesStart<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let mut value = None;

    for attribute in start.attributes() {
        let attribute = attribute?;
        let key = attribute.key.as_ref();
        if attribute_is_namespace_declaration(key) {
            continue;
        }

        if key == b"Value" {
            value = Some(String::from_utf8_lossy(attribute.value.as_ref()).into_owned());
        } else {
            return reduced_response_shell_error(
                "reduced signed response shell StatusCode contains an unexpected attribute",
            );
        }
    }

    match value.as_deref() {
        Some(SAML_STATUS_SUCCESS) => Ok(()),
        Some(code) => reduced_response_shell_error(format!(
            "reduced signed response shell StatusCode is not successful: {code}"
        )),
        None => reduced_response_shell_error(
            "reduced signed response shell StatusCode is missing Value",
        ),
    }
}

fn standalone_assertion_start(
    start: BytesStart<'_>,
    namespace_stack: &[Vec<(String, String)>],
) -> Result<BytesStart<'static>, Box<dyn std::error::Error>> {
    let declared_on_assertion = namespace_stack.last().cloned().unwrap_or_default();
    let mut standalone = start.into_owned();

    for (prefix, href) in in_scope_namespaces(namespace_stack) {
        if namespace_is_declared(&declared_on_assertion, &prefix) {
            continue;
        }

        let attribute_name = namespace_attribute_name(&prefix);
        standalone.push_attribute((attribute_name.as_str(), href.as_str()));
    }

    Ok(standalone)
}

fn namespace_declarations(
    start: &BytesStart<'_>,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut declarations = Vec::new();

    for attribute in start.attributes() {
        let attribute = attribute?;
        let key = String::from_utf8_lossy(attribute.key.as_ref());
        let prefix = if key == "xmlns" {
            Some(String::new())
        } else {
            key.strip_prefix("xmlns:").map(ToString::to_string)
        };

        if let Some(prefix) = prefix {
            declarations.push((
                prefix,
                String::from_utf8_lossy(attribute.value.as_ref()).into_owned(),
            ));
        }
    }

    Ok(declarations)
}

fn in_scope_namespaces(namespace_stack: &[Vec<(String, String)>]) -> Vec<(String, String)> {
    let mut namespaces = Vec::new();

    for frame in namespace_stack {
        for (prefix, href) in frame {
            if let Some(existing) = namespaces
                .iter_mut()
                .find(|(existing_prefix, _)| existing_prefix == prefix)
            {
                existing.1 = href.clone();
            } else {
                namespaces.push((prefix.clone(), href.clone()));
            }
        }
    }

    namespaces
}

fn namespace_is_declared(declarations: &[(String, String)], prefix: &str) -> bool {
    declarations
        .iter()
        .any(|(declared_prefix, _)| declared_prefix == prefix)
}

fn namespace_attribute_name(prefix: &str) -> String {
    if prefix.is_empty() {
        "xmlns".to_string()
    } else {
        format!("xmlns:{prefix}")
    }
}

fn element_is(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
    expected_namespace: &str,
    expected_local_name: &str,
) -> bool {
    matches!(namespace, ResolveResult::Bound(bound) if bound.as_ref() == expected_namespace.as_bytes())
        && local_name_is(local_name, expected_local_name)
}

fn local_name_is(local_name: &[u8], expected: &str) -> bool {
    local_name == expected.as_bytes()
}

fn attribute_is_namespace_declaration(attribute_name: &[u8]) -> bool {
    attribute_name == b"xmlns" || attribute_name.starts_with(b"xmlns:")
}

fn xml_text_is_whitespace(text: &[u8]) -> bool {
    text.iter()
        .all(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
}

fn reduced_response_shell_error<T>(
    message: impl Into<String>,
) -> Result<T, Box<dyn std::error::Error>> {
    Err(Box::new(DeError::Custom(message.into())))
}

fn parse_certificates(key_descriptor: &KeyDescriptor) -> Result<Vec<CertificateDer>, Error> {
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
        let encoded = general_purpose::STANDARD.encode(self.to_string()?.as_bytes());
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
            encoder.write_all(self.to_string()?.as_bytes())?;
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

    // todo: how does this fit to the seperate crypto?
    #[cfg(feature = "xmlsec")]
    pub fn signed_redirect(
        &self,
        relay_state: &str,
        private_key: &<Crypto as CryptoProvider>::PrivateKey,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let unsigned_url = self.redirect(relay_state)?;
        match unsigned_url {
            None => Ok(None),
            Some(url) => {
                let signed_url = sign_url(url, private_key)?;
                Ok(Some(signed_url))
            }
        }
    }

    #[cfg(not(feature = "xmlsec"))]
    pub fn signed_redirect(
        &self,
        _relay_state: &str,
        _private_key: &<Crypto as CryptoProvider>::PrivateKey,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        Err(Box::new(CryptoError::CryptoDisabled))
    }
}

#[cfg(test)]
mod reduced_response_shell_tests {
    use super::*;

    const DIRECT_ASSERTION_SHELL: &str = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion/>
</saml2p:Response>
"#;

    #[test]
    fn reduced_response_shell_accepts_single_direct_assertion_and_reconstructs_inherited_namespaces(
    ) {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
                 xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <Assertion>
    <Issuer>http://idp.example.com/metadata.php</Issuer>
  </Assertion>
</saml2p:Response>
"#;

        let assertion_xml = verified_assertion_from_response_shell(xml)
            .expect("single direct SAML assertion should be extracted");

        assert!(assertion_xml.starts_with("<Assertion"));
        assert!(assertion_xml.contains("xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
        assert!(assertion_xml.contains("xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""));
        assert!(assertion_xml.contains("<Issuer>http://idp.example.com/metadata.php</Issuer>"));
    }

    #[test]
    fn reduced_response_shell_accepts_success_status_and_single_direct_assertion() {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml:Assertion/>
</saml2p:Response>
"#;

        let assertion_xml = verified_assertion_from_response_shell(xml)
            .expect("success Status should be allowed in the reduced shell");

        assert!(assertion_xml.starts_with("<saml:Assertion"));
    }

    #[test]
    fn reduced_response_shell_rejects_non_success_status() {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
  </saml2p:Status>
  <saml:Assertion/>
</saml2p:Response>
"#;

        assert!(verified_assertion_from_response_shell(xml).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_multiple_direct_assertions() {
        let xml = DIRECT_ASSERTION_SHELL.replace(
            "  <saml:Assertion/>",
            "  <saml:Assertion/>\n  <saml:Assertion/>",
        );

        assert!(verified_assertion_from_response_shell(&xml).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_wrong_namespace_assertion() {
        let wrong_namespace = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:evil="urn:example:evil">
  <evil:Assertion/>
</saml2p:Response>
"#;
        let no_namespace = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion/>
</saml2p:Response>
"#;

        assert!(verified_assertion_from_response_shell(wrong_namespace).is_err());
        assert!(verified_assertion_from_response_shell(no_namespace).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_nested_assertion() {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <Container>
    <saml:Assertion/>
  </Container>
</saml2p:Response>
"#;

        assert!(verified_assertion_from_response_shell(xml).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_assertion_nested_inside_direct_assertion() {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Assertion/>
  </saml:Assertion>
</saml2p:Response>
"#;

        assert!(verified_assertion_from_response_shell(xml).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_signature_object_assertion() {
        let xml = r#"
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:Object>
      <saml:Assertion/>
    </ds:Object>
  </ds:Signature>
</saml2p:Response>
"#;

        assert!(verified_assertion_from_response_shell(xml).is_err());
    }

    #[test]
    fn reduced_response_shell_rejects_response_attributes() {
        let xml = DIRECT_ASSERTION_SHELL.replace(
            "<saml2p:Response ",
            "<saml2p:Response ID=\"unsigned-wrapper\" ",
        );

        assert!(verified_assertion_from_response_shell(&xml).is_err());
    }

    #[test]
    fn saml_root_element_classifies_only_saml_protocol_response_and_assertion_roots() {
        let protocol_response =
            r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
        let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;
        let local_name_only_response = r#"<Response xmlns="urn:example:wrong"/>"#;
        let wrong_namespace_assertion = r#"<evil:Assertion xmlns:evil="urn:example:evil"/>"#;

        assert_eq!(
            saml_root_element(protocol_response).unwrap(),
            Some(SamlRootElement::ProtocolResponse)
        );
        assert_eq!(
            saml_root_element(assertion).unwrap(),
            Some(SamlRootElement::Assertion)
        );
        assert_eq!(
            saml_root_element(local_name_only_response).unwrap(),
            Some(SamlRootElement::Unsupported)
        );
        assert_eq!(
            saml_root_element(wrong_namespace_assertion).unwrap(),
            Some(SamlRootElement::Unsupported)
        );
    }
}
