use crate::crypto::{Crypto, CryptoProvider};
use crate::schema::{Conditions, Issuer, NameIdPolicy, RequestedAuthnContext, Subject};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;
use std::str::FromStr;
use thiserror::Error;

const NAME: &str = "saml2p:AuthnRequest";
const SCHEMA: (&str, &str) = ("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnRequest {
    #[serde(rename = "@ID")]
    pub id: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "@Destination")]
    pub destination: Option<String>,
    #[serde(rename = "@Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Subject")]
    pub subject: Option<Subject>,
    #[serde(rename = "NameIDPolicy")]
    pub name_id_policy: Option<NameIdPolicy>,
    #[serde(rename = "Conditions")]
    pub conditions: Option<Conditions>,
    #[serde(rename = "RequestedAuthnContext")]
    pub requested_authn_context: Option<RequestedAuthnContext>,
    #[serde(rename = "@ForceAuthn")]
    pub force_authn: Option<bool>,
    #[serde(rename = "@IsPassive")]
    pub is_passive: Option<bool>,
    #[serde(rename = "@AssertionConsumerServiceIndex")]
    pub assertion_consumer_service_index: Option<usize>,
    #[serde(rename = "@AssertionConsumerServiceURL")]
    pub assertion_consumer_service_url: Option<String>,
    #[serde(rename = "@ProtocolBinding")]
    pub protocol_binding: Option<String>,
    #[serde(rename = "@AttributeConsumingServiceIndex")]
    pub attribute_consuming_service_index: Option<usize>,
    #[serde(rename = "@ProviderName")]
    pub provider_name: Option<String>,
}

impl Default for AuthnRequest {
    fn default() -> Self {
        AuthnRequest {
            id: "".to_string(),
            version: "".to_string(),
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: None,
            signature: None,
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: None,
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to deserialize AuthnRequest: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },

    #[error("No subject name ID")]
    NoSubjectNameID,
}

impl FromStr for AuthnRequest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl AuthnRequest {
    pub fn subject_name_id(&self) -> Result<String, Error> {
        Ok(self
            .subject
            .clone()
            .and_then(|s| s.name_id)
            .ok_or(Error::NoSubjectNameID)?
            .value)
    }

    pub fn issuer_at(&self) -> &DateTime<Utc> {
        &self.issue_instant
    }

    pub fn issuer_value(&self) -> Option<String> {
        self.issuer.clone().and_then(|iss| iss.value)
    }

    pub fn add_key_info(&mut self, public_cert_der: &[u8]) -> &mut Self {
        if let Some(ref mut signature) = self.signature {
            signature.add_key_info(public_cert_der);
        }
        self
    }

    #[cfg(feature = "xmlsec")]
    pub fn to_signed_xml(
        &self,
        private_key_der: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        use crate::traits::ToXml;

        Crypto::sign_xml(self.to_string()?, private_key_der)
            .map_err(|crypto_error| Box::new(crypto_error) as Box<dyn std::error::Error>)
    }
}

impl TryFrom<AuthnRequest> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthnRequest) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthnRequest> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthnRequest) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(NAME);
        root.push_attribute(SCHEMA);
        root.push_attribute(("ID", value.id.as_ref()));
        root.push_attribute(("Version", value.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            value
                .issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));

        if let Some(destination) = &value.destination {
            root.push_attribute(("Destination", destination.as_ref()));
        }
        if let Some(consent) = &value.consent {
            root.push_attribute(("Consent", consent.as_ref()));
        }
        if let Some(force_authn) = &value.force_authn {
            root.push_attribute(("ForceAuthn", force_authn.to_string().as_ref()));
        }
        if let Some(is_passive) = &value.is_passive {
            root.push_attribute(("IsPassive", is_passive.to_string().as_ref()));
        }
        if let Some(protocol_binding) = &value.protocol_binding {
            root.push_attribute(("ProtocolBinding", protocol_binding.as_ref()));
        }
        if let Some(assertion_consumer_service_index) = &value.assertion_consumer_service_index {
            root.push_attribute((
                "AssertionConsumerServiceIndex",
                assertion_consumer_service_index.to_string().as_ref(),
            ));
        }
        if let Some(assertion_consumer_service_url) = &value.assertion_consumer_service_url {
            root.push_attribute((
                "AssertionConsumerServiceURL",
                assertion_consumer_service_url.as_ref(),
            ));
        }
        if let Some(attribute_consuming_service_index) = &value.attribute_consuming_service_index {
            root.push_attribute((
                "AttributeConsumingServiceIndex",
                attribute_consuming_service_index.to_string().as_ref(),
            ));
        }
        if let Some(provider_name) = &value.provider_name {
            root.push_attribute(("ProviderName", provider_name.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &value.issuer {
            let event: Event<'_> = issuer.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(subject) = &value.subject {
            let event: Event<'_> = subject.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(name_id_policy) = &value.name_id_policy {
            let event: Event<'_> = name_id_policy.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(conditions) = &value.conditions {
            let event: Event<'_> = conditions.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(requested_authn_context) = &value.requested_authn_context {
            let event: Event<'_> = requested_authn_context.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::UrlVerifier;

    #[test]
    #[cfg(feature = "xmlsec")]
    pub fn test_signed_authn() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let public_cert = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/public.der"
        ));

        let authn_request_sign_template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/authn_request_sign_template.xml"
        ));

        let signed_authn_request = authn_request_sign_template
            .parse::<AuthnRequest>()?
            .add_key_info(public_cert)
            .to_signed_xml(private_key)?;

        assert!(
            Crypto::verify_signed_xml(signed_authn_request, &public_cert[..], Some("ID"),).is_ok()
        );

        Ok(())
    }

    #[test]
    pub fn test_redirect_signature() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let public_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/public_key.pem"
        ));

        let authn_request_sign_template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/authn_request_sign_template.xml"
        ));

        let private_key = openssl::rsa::Rsa::private_key_from_der(private_key).unwrap();
        let private_key = openssl::pkey::PKey::from_rsa(private_key).unwrap();

        let signed_authn_redirect_url = authn_request_sign_template
            .parse::<AuthnRequest>()?
            .signed_redirect("", private_key)?
            .unwrap();

        let url_verifier = UrlVerifier::from_rsa_pem(public_key)?;
        assert!(url_verifier.verify_signed_request_url(&signed_authn_redirect_url)?);

        Ok(())
    }

    #[test]
    pub fn test_redirect_signature_with_relaystate() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let public_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/public_key.der"
        ));

        let authn_request_sign_template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/authn_request_sign_template.xml"
        ));

        let private_key = openssl::rsa::Rsa::private_key_from_der(private_key).unwrap();
        let private_key = openssl::pkey::PKey::from_rsa(private_key).unwrap();

        let signed_authn_redirect_url = authn_request_sign_template
            .parse::<AuthnRequest>()?
            .signed_redirect("some_relay_state_here", private_key)?
            .unwrap();

        let url_verifier = UrlVerifier::from_rsa_der(public_key)?;
        assert!(url_verifier.verify_signed_request_url(&signed_authn_redirect_url)?);

        Ok(())
    }

    #[test]
    pub fn test_redirect_signature_with_relaystate_using_x509_cert(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let public_cert = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_2_metadata_public.pem"
        ));

        let authn_request_sign_template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/authn_request_sign_template.xml"
        ));

        let private_key = openssl::rsa::Rsa::private_key_from_der(private_key).unwrap();
        let private_key = openssl::pkey::PKey::from_rsa(private_key).unwrap();

        let signed_authn_redirect_url = authn_request_sign_template
            .parse::<AuthnRequest>()?
            .signed_redirect("some_relay_state_here", private_key)?
            .unwrap();

        let url_verifier = UrlVerifier::from_x509_cert_pem(public_cert)?;
        assert!(url_verifier.verify_signed_request_url(&signed_authn_redirect_url)?);

        Ok(())
    }
}
