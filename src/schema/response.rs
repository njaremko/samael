use crate::schema::{Assertion, Issuer, Status};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;
use std::str::FromStr;
use thiserror::Error;

use super::EncryptedAssertion;

const NAME: &str = "saml2p:Response";
const SCHEMA: (&str, &str) = ("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct Response {
    #[serde(rename = "@ID")]
    pub id: String,
    #[serde(rename = "@InResponseTo")]
    #[builder(setter(strip_option))]
    pub in_response_to: Option<String>,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@IssueInstant")]
    #[builder(setter(strip_option))]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "@Destination")]
    #[builder(setter(strip_option))]
    pub destination: Option<String>,
    #[serde(rename = "@Consent")]
    #[builder(setter(strip_option))]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    #[builder(setter(strip_option))]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    #[builder(setter(strip_option))]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    #[builder(setter(strip_option))]
    pub status: Option<Status>,
    #[serde(rename = "EncryptedAssertion")]
    #[builder(setter(strip_option))]
    pub encrypted_assertion: Option<Vec<EncryptedAssertion>>,
    #[serde(rename = "Assertion")]
    #[builder(setter(strip_option))]
    pub assertions: Option<Vec<Assertion>>,
    #[serde(rename = "EncryptedAssertion")]
    #[builder(setter(strip_option))]
    pub encrypted_assertions: Option<Vec<EncryptedAssertion>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to deserialize SAMLResponse: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<Response> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Response> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Response) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(NAME);
        root.push_attribute(SCHEMA);
        root.push_attribute(("ID", value.id.as_ref()));
        if let Some(resp_to) = &value.in_response_to {
            root.push_attribute(("InResponseTo", resp_to.as_ref()));
        }
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

        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &value.issuer {
            let event: Event<'_> = issuer.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(status) = &value.status {
            let event: Event<'_> = status.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(assertions) = &value.assertions {
            for assertion in assertions.iter() {
                let event: Event<'_> = assertion.try_into()?;
                writer.write_event(event)?;
            }
        }

        // Handling encrypted assertions.
        if let Some(assertions) = &value.encrypted_assertions {
            for assertion in assertions.iter() {
                let event: Event<'_> = assertion.try_into()?;
                writer.write_event(event)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use super::Response;
    use crate::traits::ToXml;

    #[test]
    fn test_deserialize_serialize_response() {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response.xml",
        ));
        let expected_response: Response =
            response_xml.parse().expect("failed to parse response.xml");
        let serialized_response = expected_response
            .to_xml()
            .expect("failed to convert response to xml");
        let actual_response: Response = serialized_response
            .parse()
            .expect("failed to re-parse response");

        assert_eq!(expected_response, actual_response);
    }

    #[test]
    fn test_deserialize_serialize_response_with_signed_assertion() {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_assertion.xml",
        ));
        let expected_response: Response = response_xml
            .parse()
            .expect("failed to parse response_signed_assertion.xml");
        let serialized_response = expected_response
            .to_xml()
            .expect("failed to convert response to xml");
        let actual_response: Response = serialized_response
            .parse()
            .expect("failed to re-parse response");

        assert_eq!(expected_response, actual_response);
    }

    #[test]
    fn test_deserialize_serialize_signed_response() {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed.xml",
        ));
        let expected_response: Response = response_xml
            .parse()
            .expect("failed to parse response_signed.xml");
        let serialized_response = expected_response
            .to_xml()
            .expect("failed to convert response to xml");
        let actual_response: Response = serialized_response
            .parse()
            .expect("failed to re-parse response");

        assert_eq!(expected_response, actual_response);
    }
}
