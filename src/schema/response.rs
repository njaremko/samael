use crate::schema::{Assertion, Issuer, Status};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use snafu::Snafu;
use std::io::Cursor;
use std::str::FromStr;

const NAME: &str = "saml2p:Response";
const SCHEMA: (&str, &str) = ("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Response {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    pub status: Status,
    #[serde(rename = "EncryptedAssertion")]
    pub encrypted_assertion: Option<String>,
    #[serde(rename = "Assertion")]
    pub assertion: Option<Assertion>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize SAMLResponse: {:?}", source))]
    #[snafu(context(false))]
    ParseError { source: quick_xml::DeError },
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl Response {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new(
            "1.0".as_bytes(),
            Some("UTF-8".as_bytes()),
            None,
        )))?;

        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);
        root.push_attribute(("ID", self.id.as_ref()));
        if let Some(resp_to) = &self.in_response_to {
            root.push_attribute(("InResponseTo", resp_to.as_ref()));
        }
        root.push_attribute(("Version", self.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            self.issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));
        if let Some(destination) = &self.destination {
            root.push_attribute(("Destination", destination.as_ref()));
        }
        if let Some(consent) = &self.consent {
            root.push_attribute(("Consent", consent.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &self.issuer {
            writer.write(issuer.to_xml()?.as_bytes())?;
        }
        if let Some(signature) = &self.signature {
            writer.write(signature.to_xml()?.as_bytes())?;
        }

        writer.write(self.status.to_xml()?.as_bytes())?;

        if let Some(assertion) = &self.assertion {
            writer.write(assertion.to_xml()?.as_bytes())?;
        }

        // TODO: encrypted assertion
        // if let Some(assertion) = &self.encrypted_assertion {
        //     writer.write(assertion.to_xml()?.as_bytes())?;
        // }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[cfg(test)]
mod test {
    use super::Response;

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
