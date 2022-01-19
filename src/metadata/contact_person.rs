use yaserde_derive::{YaDeserialize, YaSerialize};

pub enum ContactType {
    Technical,
    Support,
    Administrative,
    Billing,
    Other,
}

impl ContactType {
    pub fn value(&self) -> &'static str {
        match self {
            ContactType::Technical => "technical",
            ContactType::Support => "support",
            ContactType::Administrative => "administrative",
            ContactType::Billing => "billing",
            ContactType::Other => "other",
        }
    }
}

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct ContactPerson {
    #[yaserde(attribute, rename = "contactType")]
    pub contact_type: String,
    #[yaserde(rename = "Company", prefix = "md")]
    pub company: Option<String>,
    #[yaserde(rename = "GivenName", prefix = "md")]
    pub given_name: Option<String>,
    #[yaserde(rename = "SurName", prefix = "md")]
    pub surname: Option<String>,
    #[yaserde(rename = "EmailAddress", prefix = "md", default)]
    pub email_addresses: Vec<String>,
    #[yaserde(rename = "TelephoneNumber", prefix = "md", default)]
    pub telephone_numbers: Vec<String>,
}
