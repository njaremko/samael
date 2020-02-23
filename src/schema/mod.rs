mod authn_request;
mod conditions;
mod issuer;
mod name_id_policy;
mod subject;

pub use authn_request::AuthnRequest;
pub use conditions::*;
pub use issuer::Issuer;
pub use name_id_policy::NameIdPolicy;
pub use subject::*;

use crate::attribute::Attribute;
use crate::signature::Signature;
use chrono::prelude::*;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct LogoutRequest {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "SessionIndex")]
    pub session_index: Option<String>,
}

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

#[derive(Clone, Debug, Deserialize)]
pub struct Assertion {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "ds:Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Subject")]
    pub subject: Option<Subject>,
    #[serde(rename = "Conditions")]
    pub conditions: Option<Conditions>,
    #[serde(rename = "AuthnStatement")]
    pub authn_statements: Vec<AuthnStatement>,
    #[serde(rename = "AttributeStatement")]
    pub attribute_statements: Vec<AttributeStatement>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AttributeStatement {
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthnStatement {
    #[serde(rename = "AuthnInstant")]
    pub authn_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "SessionIndex")]
    pub session_index: Option<String>,
    #[serde(rename = "SessionNotOnOrAfter")]
    pub session_not_on_or_after: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "SubjectLocality")]
    pub subject_locality: Option<SubjectLocality>,
    #[serde(rename = "AuthnContext")]
    pub authn_content: Option<AuthnContext>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SubjectLocality {
    #[serde(rename = "Address")]
    pub address: Option<String>,
    #[serde(rename = "DNSName")]
    pub dns_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Status {
    #[serde(rename = "StatusCode")]
    pub status_code: StatusCode,
    #[serde(rename = "StatusMessage")]
    pub status_message: Option<StatusMessage>,
    #[serde(rename = "StatusDetail")]
    pub status_detail: Option<StatusDetail>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StatusCode {
    #[serde(rename = "Value")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StatusMessage {
    #[serde(rename = "Value")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StatusDetail {
    #[serde(rename = "Children")]
    pub children: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LogoutResponse {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    pub status: Option<Status>,
}
