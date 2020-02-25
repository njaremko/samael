use crate::schema::{Assertion, Issuer, Status};
use crate::signature::Signature;
use chrono::prelude::*;
use serde::Deserialize;
use snafu::Snafu;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize)]
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
