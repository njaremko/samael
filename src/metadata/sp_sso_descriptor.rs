use crate::{
    metadata::{
        AttributeConsumingService, ContactPerson, Endpoint, IndexedEndpoint, KeyDescriptor,
        Organization,
    },
    signature::Signature,
    utils::UtcDateTime,
};
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct SpSsoDescriptor {
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(attribute, rename = "validUntil")]
    pub valid_until: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "cacheDuration")]
    pub cache_duration: Option<String>,
    #[yaserde(attribute, rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: String,
    #[yaserde(attribute, rename = "errorURL")]
    pub error_url: Option<String>,
    #[yaserde(attribute, rename = "AuthnRequestsSigned")]
    pub authn_requests_signed: Option<bool>,
    #[yaserde(attribute, rename = "WantAssertionsSigned")]
    pub want_assertions_signed: Option<bool>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
    #[yaserde(rename = "ArtifactResolutionService", prefix = "md", default)]
    pub artifact_resolution_service: Vec<IndexedEndpoint>,
    #[yaserde(rename = "SingleLogoutService", prefix = "md", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[yaserde(rename = "ManageNameIDService", prefix = "md", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDFormat", prefix = "md", default)]
    pub name_id_formats: Vec<String>,
    #[yaserde(rename = "AssertionConsumerService", prefix = "md")]
    pub assertion_consumer_services: Vec<IndexedEndpoint>,
    #[yaserde(rename = "AttributeConsumingService", prefix = "md", default)]
    pub attribute_consuming_services: Vec<AttributeConsumingService>,
}
