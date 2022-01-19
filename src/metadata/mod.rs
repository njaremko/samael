mod affiliation_descriptor;
mod attribute_consuming_service;
mod contact_person;
mod encryption_method;
mod endpoint;
mod entity_descriptor;
mod key_descriptor;
mod organization;
mod sp_sso_descriptor;

pub use affiliation_descriptor::*;
pub use attribute_consuming_service::AttributeConsumingService;
pub use contact_person::*;
pub use encryption_method::EncryptionMethod;
pub use endpoint::*;
pub use entity_descriptor::{EntitiesDescriptor, EntityDescriptor};
pub use key_descriptor::KeyDescriptor;
pub use organization::Organization;
pub use sp_sso_descriptor::SpSsoDescriptor;
use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::attribute::Attribute;
use crate::signature::Signature;
use crate::utils::UtcDateTime;

// HTTP_POST_BINDING is the official URN for the HTTP-POST binding (transport)
pub const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// HTTP_REDIRECT_BINDING is the official URN for the HTTP-Redirect binding (transport)
pub const HTTP_REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum NameIdFormat {
    UnspecifiedNameIDFormat,
    TransientNameIDFormat,
    EmailAddressNameIDFormat,
    PersistentNameIDFormat,
}

impl NameIdFormat {
    pub fn value(&self) -> &'static str {
        match self {
            NameIdFormat::UnspecifiedNameIDFormat => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            }
            NameIdFormat::TransientNameIDFormat => {
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            }
            NameIdFormat::EmailAddressNameIDFormat => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            }
            NameIdFormat::PersistentNameIDFormat => {
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
            }
        }
    }
}

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct RoleDescriptor {
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(attribute, rename = "validUntil")]
    pub valid_until: Option<UtcDateTime>,
    #[yaserde(attribute, rename = "cacheDuration")]
    pub cache_duration: Option<u32>,
    #[yaserde(attribute, rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: String,
    #[yaserde(attribute, rename = "errorURL")]
    pub error_url: Option<String>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion"
)]
pub struct IdpSsoDescriptor {
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
    #[yaserde(attribute, rename = "WantAuthnRequestsSigned")]
    pub want_authn_requests_signed: Option<bool>,
    #[yaserde(rename = "Signature", namespace = "ds")]
    pub signature: Option<String>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
    #[yaserde(rename = "ArtifactResolutionService", prefix = "md", default)]
    pub artifact_resolution_services: Vec<IndexedEndpoint>,
    #[yaserde(rename = "SingleLogoutService", prefix = "md", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[yaserde(rename = "ManageNameIDService", prefix = "md", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDFormat", prefix = "md", default)]
    pub name_id_formats: Vec<String>,
    #[yaserde(rename = "SingleSignOnService", prefix = "md")]
    pub single_sign_on_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDMappingService", prefix = "md", default)]
    pub name_id_mapping_services: Vec<Endpoint>,
    #[yaserde(rename = "AssertionIDRequestService", prefix = "md", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[yaserde(rename = "AttributeProfile", prefix = "md", default)]
    pub attribute_profiles: Vec<String>,
    #[yaserde(rename = "Attribute", prefix = "saml", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct AuthnAuthorityDescriptors {
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
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
    #[yaserde(rename = "AuthnQueryService", prefix = "md")]
    pub authn_query_services: Vec<Endpoint>,
    #[yaserde(rename = "AssertionIDRequestService", prefix = "md", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDFormat", prefix = "md", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion"
)]
pub struct AttributeAuthorityDescriptors {
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
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
    #[yaserde(rename = "AttributeService", prefix = "md")]
    pub attribute_services: Vec<Endpoint>,
    #[yaserde(rename = "AssertionIDRequestService", prefix = "md", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDFormat", prefix = "md", default)]
    pub name_id_formats: Vec<String>,
    #[yaserde(rename = "AttributeProfile", prefix = "md", default)]
    pub attribute_profiles: Vec<String>,
    #[yaserde(rename = "Attribute", prefix = "saml", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct PdpDescriptor {
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
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "KeyDescriptor", prefix = "md", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[yaserde(rename = "Organization", prefix = "md")]
    pub organization: Option<Organization>,
    #[yaserde(rename = "ContactPerson", prefix = "md", default)]
    pub contact_people: Vec<ContactPerson>,
    #[yaserde(rename = "AuthzService", prefix = "md")]
    pub authz_services: Vec<Endpoint>,
    #[yaserde(rename = "AssertionIDRequestService", prefix = "md", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[yaserde(rename = "NameIDFormat", prefix = "md", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Debug, Clone, YaDeserialize, YaSerialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedName {
    #[yaserde(attribute, prefix = "xml")]
    lang: Option<String>,
    #[yaserde(text)]
    value: String,
}

#[derive(Debug, Clone, YaDeserialize, YaSerialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedUri {
    #[yaserde(attribute, prefix = "xml")]
    lang: Option<String>,
    #[yaserde(text)]
    value: String,
}
