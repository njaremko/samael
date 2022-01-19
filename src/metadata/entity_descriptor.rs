use crate::metadata::{
    AffiliationDescriptor, AttributeAuthorityDescriptors, AuthnAuthorityDescriptors, ContactPerson,
    IdpSsoDescriptor, Organization, PdpDescriptor, RoleDescriptor, SpSsoDescriptor,
};
use crate::signature::Signature;
use crate::utils::UtcDateTime;
use snafu::Snafu;
use std::str::FromStr;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    root,
    prefix = "md",
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct EntityDescriptor {
    #[yaserde(attribute, rename = "entityID")]
    pub entity_id: String,
    #[yaserde(attribute, rename = "validUntil")]
    pub valid_until: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "cacheDuration")]
    pub cache_duration: Option<String>,
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "RoleDescriptor", prefix = "md", default)]
    pub role_descriptors: Vec<RoleDescriptor>,
    #[yaserde(rename = "IDPSSODescriptor", prefix = "md", default)]
    pub idp_sso_descriptors: Vec<IdpSsoDescriptor>,
    #[yaserde(rename = "SPSSODescriptor", prefix = "md", default)]
    pub sp_sso_descriptors: Vec<SpSsoDescriptor>,
    #[yaserde(rename = "AuthnAuthorityDescriptor", prefix = "md", default)]
    pub authn_authority_descriptors: Vec<AuthnAuthorityDescriptors>,
    #[yaserde(rename = "AttributeAuthorityDescriptor", prefix = "md", default)]
    pub attribute_authority_descriptors: Vec<AttributeAuthorityDescriptors>,
    #[yaserde(rename = "PDPDescriptor", prefix = "md", default)]
    pub pdp_descriptors: Vec<PdpDescriptor>,
    #[yaserde(rename = "AffiliationDescriptor", prefix = "md")]
    pub affiliation_descriptors: Option<AffiliationDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_person: Vec<ContactPerson>,
    #[yaserde(rename = "AdditionalMetadataLocation", prefix = "md", default)]
    pub additional_metadata_locations: Vec<AdditionalMetadataLocation>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize SAML response: {message:?}"))]
    ParseError { message: String },
}

impl FromStr for EntityDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        yaserde::de::from_str(s).map_err(|message| Error::ParseError { message })
    }
}

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct AdditionalMetadataLocation {
    #[yaserde(attribute)]
    namespace: String,
    #[yaserde(text)]
    value: String,
}

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    root,
    prefix = "md",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct EntitiesDescriptor {
    #[yaserde(prefix = "md", rename = "EntityDescriptor")]
    pub descriptors: Vec<EntityDescriptor>,
}

#[cfg(test)]
mod test {
    use super::EntityDescriptor;

    #[test]
    fn test_sp_entity_descriptor() {
        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/sp_metadata.xml"
        ));
        let entity_descriptor: EntityDescriptor = input_xml
            .parse()
            .expect("Failed to parse sp_metadata.xml into an EntityDescriptor");
        let output_xml = yaserde::ser::to_string(&entity_descriptor)
            .expect("Failed to convert EntityDescriptor to xml");
        let reparsed_entity_descriptor: EntityDescriptor = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptor");

        assert_eq!(reparsed_entity_descriptor, entity_descriptor);
    }

    #[test]
    fn test_idp_entity_descriptor() {
        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_metadata.xml"
        ));
        let entity_descriptor: EntityDescriptor = input_xml
            .parse()
            .expect("Failed to parse sp_metadata.xml into an EntityDescriptor");
        let output_xml = yaserde::ser::to_string(&entity_descriptor)
            .expect("Failed to convert EntityDescriptor to xml");
        let reparsed_entity_descriptor: EntityDescriptor = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptor");

        assert_eq!(reparsed_entity_descriptor, entity_descriptor);
    }
}
