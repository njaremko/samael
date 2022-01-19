use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::{metadata::KeyDescriptor, signature::Signature, utils::UtcDateTime};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion"
)]
pub struct AffiliationDescriptor {
    #[yaserde(attribute, rename = "affiliationOwnerID")]
    pub affiliation_owner_id: String,
    #[yaserde(attribute, rename = "validUntil")]
    pub valid_until: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "cacheDuration")]
    pub cache_duration: String,
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(rename = "Signature", prefix = "sd")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "AffiliateMember", prefix = "md")]
    pub affiliate_members: Vec<String>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
}
