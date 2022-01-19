use crate::metadata::{LocalizedName, LocalizedUri};
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct Organization {
    #[yaserde(rename = "OrganizationName", prefix = "md")]
    pub organization_names: Vec<LocalizedName>,
    #[yaserde(rename = "OrganizationDisplayName", prefix = "md")]
    pub organization_display_names: Vec<LocalizedName>,
    #[yaserde(rename = "OrganizationURL", prefix = "md")]
    pub organization_urls: Vec<LocalizedUri>,
}
