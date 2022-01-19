mod assertion;
pub mod authn_request;
mod conditions;
pub mod encrypted_assertion;
mod issuer;
mod name_id;
mod name_id_policy;
mod response;
mod subject;

pub use assertion::Assertion;
pub use authn_request::AuthnRequest;
pub use conditions::*;
pub use encrypted_assertion::EncryptedAssertion;
pub use issuer::Issuer;
pub use name_id::NameId;
pub use name_id_policy::NameIdPolicy;
pub use response::Response;
pub use subject::*;
use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::attribute::Attribute;
use crate::signature::Signature;
use crate::utils::UtcDateTime;

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    root,
    prefix = "samlp",
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion",
    namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol"
)]
pub struct LogoutRequest {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "Version")]
    pub version: String,
    #[yaserde(attribute, rename = "IssueInstant")]
    pub issue_instant: UtcDateTime,
    #[yaserde(attribute, rename = "Destination")]
    pub destination: Option<String>,
    #[yaserde(attribute, rename = "Consent")]
    pub consent: Option<String>,
    #[yaserde(attribute, rename = "Reason")]
    pub reason: Option<String>,
    #[yaserde(attribute, rename = "NotOnOrAfter")]
    pub not_on_or_after: Option<UtcDateTime>,
    #[yaserde(rename = "Issuer", prefix = "saml")]
    pub issuer: Option<Issuer>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "NameID", prefix = "samlp")] // TODO: choice BaseID/NameID/EncryptedID
    pub name_id: Option<NameId>,
    #[yaserde(rename = "SessionIndex", prefix = "samlp")]
    pub session_index: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct AttributeStatement {
    #[yaserde(rename = "Attribute", prefix = "saml")]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct AuthnStatement {
    #[yaserde(attribute, rename = "AuthnInstant")]
    pub authn_instant: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "SessionIndex")]
    pub session_index: Option<String>,
    #[yaserde(attribute, rename = "SessionNotOnOrAfter")]
    pub session_not_on_or_after: Option<UtcDateTime>,
    #[yaserde(rename = "SubjectLocality", prefix = "saml")]
    pub subject_locality: Option<SubjectLocality>,
    #[yaserde(rename = "AuthnContext", prefix = "saml")]
    pub authn_context: Option<AuthnContext>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct SubjectLocality {
    #[yaserde(attribute, rename = "Address")]
    pub address: Option<String>,
    #[yaserde(attribute, rename = "DNSName")]
    pub dns_name: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct AuthnContext {
    #[yaserde(rename = "AuthnContextClassRef", prefix = "saml")]
    pub value: Option<AuthnContextClassRef>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct AuthnContextClassRef {
    #[yaserde(text)]
    pub value: Option<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol")]
pub struct Status {
    #[yaserde(rename = "StatusCode", prefix = "samlp")]
    pub status_code: StatusCode,
    #[yaserde(rename = "StatusMessage", prefix = "samlp")]
    pub status_message: Option<StatusMessage>,
    #[yaserde(rename = "StatusDetail", prefix = "samlp")]
    pub status_detail: Option<StatusDetail>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct StatusCode {
    #[yaserde(attribute, rename = "Value")]
    pub value: String,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct StatusMessage {
    #[yaserde(text)]
    pub value: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol")]
pub struct StatusDetail {
    #[yaserde(rename = "Children", prefix = "samlp")]
    pub children: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    root,
    prefix = "samlp",
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion",
    namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol"
)]
pub struct LogoutResponse {
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
}
