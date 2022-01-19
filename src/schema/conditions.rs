use crate::utils::UtcDateTime;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct Conditions {
    #[yaserde(attribute, rename = "NotBefore")]
    pub not_before: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "NotOnOrAfter")]
    pub not_on_or_after: Option<UtcDateTime>,
    #[yaserde(rename = "AudienceRestriction", prefix = "saml")]
    pub audience_restrictions: Vec<AudienceRestriction>,
    #[yaserde(rename = "OneTimeUse", prefix = "saml")]
    pub one_time_use: Option<OneTimeUse>,
    #[yaserde(rename = "ProxyRestriction", prefix = "saml")]
    pub proxy_restriction: Option<ProxyRestriction>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct AudienceRestriction {
    #[yaserde(rename = "Audience", prefix = "saml")]
    pub audience: Vec<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct OneTimeUse {}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct ProxyRestriction {
    #[yaserde(attribute, rename = "Count")]
    pub count: Option<u32>,
    #[yaserde(rename = "Audience", prefix = "saml")]
    pub audiences: Vec<String>,
}
