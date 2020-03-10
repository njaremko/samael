mod affiliation_descriptor;
mod attribute_consuming_service;
mod contact_person;
mod encryption_method;
mod endpoint;
mod entity_descriptor;
mod helpers;
mod key_descriptor;
mod localized;
mod organization;
mod sp_sso_descriptor;

pub use affiliation_descriptor::*;
pub use attribute_consuming_service::AttributeConsumingService;
pub use contact_person::*;
pub use encryption_method::EncryptionMethod;
pub use endpoint::*;
pub use entity_descriptor::EntityDescriptor;
pub use key_descriptor::KeyDescriptor;
pub use localized::*;
pub use organization::Organization;
pub use sp_sso_descriptor::SpSsoDescriptor;
pub mod de {
    pub use quick_xml::de::*;
}

use serde::Deserialize;

use crate::attribute::Attribute;
use crate::signature::Signature;
use chrono::prelude::*;

// HTTP_POST_BINDING is the official URN for the HTTP-POST binding (transport)
pub const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// HTTP_REDIRECT_BINDING is the official URN for the HTTP-Redirect binding (transport)
pub const HTTP_REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RoleDescriptor {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SSODescriptor {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "ArtifactResolutionService", default)]
    pub artifact_resolution_service: Vec<IndexedEndpoint>,
    #[serde(rename = "SingleLogoutService", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[serde(rename = "ManageNameIDService", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct IdpSsoDescriptor {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    #[serde(rename = "ArtifactResolutionService", default)]
    pub artifact_resolution_service: Vec<IndexedEndpoint>,
    #[serde(rename = "SingleLogoutService", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[serde(rename = "ManageNameIDService", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
    // ^-SSODescriptor
    #[serde(rename = "WantAuthnRequestsSigned")]
    pub want_authn_requests_signed: Option<bool>,
    #[serde(rename = "SingleSignOnService", default)]
    pub single_sign_on_services: Vec<Endpoint>,
    #[serde(rename = "NameIDMappingService", default)]
    pub name_id_mapping_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "AttributeProfile", default)]
    pub attribute_profiles: Vec<String>,
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnAuthorityDescriptors {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AuthnQueryService", default)]
    pub authn_query_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeAuthorityDescriptors {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AttributeService", default)]
    pub attribute_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
    #[serde(rename = "AttributeProfile", default)]
    pub attribute_profiles: Vec<String>,
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct PdpDescriptors {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AuthzService", default)]
    pub authz_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}
