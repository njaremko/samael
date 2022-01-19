use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::{signature::Signature, utils::UtcDateTime};

use super::{AttributeStatement, AuthnStatement, Conditions, Issuer, Subject};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion",
    namespace = "xsd: http://www.w3.org/2001/XMLSchema"
)]
pub struct Assertion {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "IssueInstant")]
    pub issue_instant: UtcDateTime,
    #[yaserde(attribute, rename = "Version")]
    pub version: String,
    #[yaserde(rename = "Issuer", prefix = "saml")]
    pub issuer: Issuer,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "Subject", prefix = "saml")]
    pub subject: Option<Subject>,
    #[yaserde(rename = "Conditions", prefix = "saml")]
    pub conditions: Option<Conditions>,
    #[yaserde(rename = "AuthnStatement", prefix = "saml")]
    pub authn_statements: Vec<AuthnStatement>,
    #[yaserde(rename = "AttributeStatement", prefix = "saml")]
    pub attribute_statements: Vec<AttributeStatement>,
}
