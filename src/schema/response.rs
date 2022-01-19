use crate::schema::{Assertion, EncryptedAssertion, Issuer, Status};
use crate::signature::Signature;
use crate::utils::UtcDateTime;
use snafu::Snafu;
use std::str::FromStr;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    root
    prefix = "samlp",
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion",
    namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol",
)]
pub struct Response {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[yaserde(attribute, rename = "Version")]
    pub version: String,
    #[yaserde(attribute, rename = "IssueInstant")]
    pub issue_instant: UtcDateTime,
    #[yaserde(attribute, rename = "Destination")]
    pub destination: Option<String>,
    #[yaserde(attribute, rename = "Consent")]
    pub consent: Option<String>,
    #[yaserde(rename = "Issuer", prefix = "saml")]
    pub issuer: Option<Issuer>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "Status", prefix = "samlp")]
    pub status: Status,
    #[yaserde(rename = "Assertion", prefix = "saml")]
    pub assertion: Option<Assertion>,
    #[yaserde(rename = "EncryptedAssertion", prefix = "saml")]
    pub encrypted_assertion: Option<EncryptedAssertion>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize SAMLResponse: {message:?}"))]
    ParseError { message: String },
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        yaserde::de::from_str(s).map_err(|message| Error::ParseError { message })
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
        let serialized_response =
            yaserde::ser::to_string(&expected_response).expect("failed to convert response to xml");
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
        let serialized_response =
            yaserde::ser::to_string(&expected_response).expect("failed to convert response to xml");
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
        let serialized_response =
            yaserde::ser::to_string(&expected_response).expect("failed to convert response to xml");
        std::fs::write("/tmp/foo.xml", &serialized_response).unwrap();
        let actual_response: Response = serialized_response
            .parse()
            .expect("failed to re-parse response");

        assert_eq!(expected_response, actual_response);
    }
}
