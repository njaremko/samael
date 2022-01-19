use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::utils::UtcDateTime;

use super::NameId;

#[derive(YaDeserialize, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub enum SubjectType {
    #[yaserde(rename = "BaseID", prefix = "saml")]
    BaseId,
    #[yaserde(rename = "NameID", prefix = "saml")]
    NameId(String),
    #[yaserde(rename = "EncryptedID", prefix = "saml")]
    EncryptedId,
}

impl Default for SubjectType {
    fn default() -> Self {
        SubjectType::BaseId
    }
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct Subject {
    #[yaserde(rename = "NameID", prefix = "saml")]
    pub name_id: Option<NameId>,
    #[yaserde(rename = "SubjectConfirmation", prefix = "saml")]
    pub subject_confirmations: Vec<SubjectConfirmation>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct SubjectConfirmation {
    #[yaserde(attribute, rename = "Method")]
    pub method: Option<String>,
    #[yaserde(rename = "NameID", prefix = "saml")]
    pub name_id: Option<NameId>,
    #[yaserde(rename = "SubjectConfirmationData", prefix = "saml")]
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct SubjectConfirmationData {
    #[yaserde(attribute, rename = "NotBefore")]
    pub not_before: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "NotOnOrAfter")]
    pub not_on_or_after: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "Recipient")]
    pub recipient: Option<String>,
    #[yaserde(attribute, rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[yaserde(attribute, rename = "Address")]
    pub address: Option<String>,
    #[yaserde(text)]
    pub content: Option<String>,
}
