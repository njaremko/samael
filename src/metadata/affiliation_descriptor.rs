use crate::metadata::KeyDescriptor;
use chrono::prelude::*;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AffiliationDescriptor {
    #[serde(rename = "affiliationOwnerID")]
    pub affiliation_descriptors: String,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: String,
    #[serde(rename = "AffiliateMember", default)]
    pub affiliate_members: Vec<String>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
}
