use crate::metadata::{
    AffiliationDescriptor, AttributeAuthorityDescriptors, AuthnAuthorityDescriptors, ContactPerson,
    IdpSsoDescriptor, Organization, PdpDescriptors, RoleDescriptor, SpSsoDescriptor,
};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(untagged)]
pub enum Entity {
    Entity(Box<EntityDescriptor>),
    Entities(Box<EntitiesDescriptor>),
}

/// The <EntitiesDescriptor> element contains the metadata for an optionally
/// named group of SAML entities.
///
/// This is one of the two possible root nodes of an XML tree for the saml
/// metadata data structure.
///
/// When used as the root element of a metadata instance, this element MUST
/// contain either a validUntil or cacheDuration attribute. It is RECOMMENDED
/// that only the root element of a metadata instance contain either attribute
///
///```XML
///
///     <element name="EntitiesDescriptor" type="md:EntitiesDescriptorType"/>
///     <complexType name="EntitiesDescriptorType">
///         <sequence>
///             <element ref="ds:Signature" minOccurs="0"/>
///             <element ref="md:Extensions" minOccurs="0"/>
///             <choice minOccurs="1" maxOccurs="unbounded">
///                 <element ref="md:EntityDescriptor"/>
///                 <element ref="md:EntitiesDescriptor"/>
///             </choice>
///         </sequence>
///         <attribute name="validUntil" type="dateTime" use="optional"/>
///         <attribute name="cacheDuration" type="duration" use="optional"/>
///         <attribute name="ID" type="ID" use="optional"/>
///         <attribute name="Name" type="string" use="optional"/>
///     </complexType>
///     <!-- We don't support extensions at all -->
///     <element name="Extensions" type="md:ExtensionsType"/>
///         <complexType final="#all" name="ExtensionsType">
///         <sequence>
///             <any namespace="##other" processContents="lax" maxOccurs="unbounded"/>
///         </sequence>
///     </complexType>
/// ```
#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename = "md:EntitiesDescriptor")]
pub struct EntitiesDescriptor {
    /// A document-unique identifier for the element, typically used as a
    /// reference point when signing.
    #[serde(rename = "@ID")]
    pub id: Option<String>,

    /// Optional attribute indicates the expiration time of the metadata
    /// contained in the element and any contained elements.
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Optional attribute indicates the maximum length of time a consumer
    /// should cache the metadata contained in the element and any contained
    /// elements.
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<String>,

    /// A string name that identifies a group of SAML entities in the context of
    /// some deployment.
    #[serde(rename = "Name")]
    pub name: Option<String>,

    /// An XML signature that authenticates the containing element and its
    /// contents.
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,

    /// This is the XML Children of the current node in addition to other nodes.
    #[serde(flatten)]
    pub children: Vec<Entity>,
}

/// This is the SAML metadata class.
///
/// The <EntityDescriptor> element specifies metadata for a single SAML entity.
/// A single entity may act in many different roles in the support of multiple
/// profiles. This specification directly supports the following concrete roles
/// as well as the abstract <RoleDescriptor> element for extensibility (see
/// subsequent sections for more details):
/// * SSO Identity Provider
/// * SSO Service Provider
/// * Authentication Authority
/// * Attribute Authority
/// * Policy Decision Point
/// * Affiliation
///
/// We don't support extensions at this time.
///
/// Must have One or more of the following:
/// * <RoleDescriptor>
/// * <IDPSSODescriptor>
/// * <SPSSODescriptor>
/// * <AuthnAuthorityDescriptor>
/// * <AttributeAuthorityDescriptor>
/// * <PDPDescriptor>
///
/// **OR** it must have one <AffiliationDescriptor>
///
/// When used as the root element of a metadata instance, this element MUST
/// contain either a validUntil or cacheDuration attribute. It is RECOMMENDED
/// that only the root element of a metadata instance contain either attribute.
///
/// It is RECOMMENDED that if multiple role descriptor elements of the same type
/// appear, that they do not share overlapping `protocolSupportEnumeration`
/// values. Selecting from among multiple role descriptor elements of the same
/// type that do share a `protocolSupportEnumeration` value is undefined within
/// this specification, but MAY be defined by metadata profiles, possibly
/// through the use of other distinguishing extension attributes.
///
/// Namespace applied to the metadata XML `urn:oasis:names:tc:SAML:2.0:metadata`
///
/// ```xml
/// <element name="EntityDescriptor" type="md:EntityDescriptorType"/>
/// <complexType name="EntityDescriptorType">
///     <sequence>
///         <element ref="ds:Signature" minOccurs="0"/>
///         <element ref="md:Extensions" minOccurs="0"/>
///         <choice>
///             <choice maxOccurs="unbounded">
///                 <element ref="md:RoleDescriptor"/>
///                 <element ref="md:IDPSSODescriptor"/>
///                 <element ref="md:SPSSODescriptor"/>
///                 <element ref="md:AuthnAuthorityDescriptor"/>
///                 <element ref="md:AttributeAuthorityDescriptor"/>
///                 <element ref="md:PDPDescriptor"/>
///             </choice>
///             <element ref="md:AffiliationDescriptor"/>
///         </choice>
///         <element ref="md:Organization" minOccurs="0"/>
///         <element ref="md:ContactPerson" minOccurs="0" maxOccurs="unbounded"/>
///         <element ref="md:AdditionalMetadataLocation" minOccurs="0" maxOccurs="unbounded"/>
///     </sequence>
///     <attribute name="entityID" type="md:entityIDType" use="required"/>
///     <attribute name="validUntil" type="dateTime" use="optional"/>
///     <attribute name="cacheDuration" type="duration" use="optional"/>
///     <attribute name="ID" type="ID" use="optional"/>
///     <anyAttribute namespace="##other" processContents="lax"/>
/// </complexType>
/// ```
#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename = "md:EntityDescriptor")]
pub struct EntityDescriptor {
    /// Specifies the unique identifier of the SAML entity whose metadata is
    /// described by the element's contents
    #[serde(rename = "@entityID")]
    pub entity_id: Option<String>,

    /// A document-unique identifier for the element, typically used as a
    /// reference point when signing.
    #[serde(rename = "@ID")]
    pub id: Option<String>,

    /// Optional attribute indicates the expiration time of the metadata
    /// contained in the element and any contained elements.
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Optional attribute indicates the maximum length of time a consumer
    /// should cache the metadata contained in the element and any contained
    /// elements.
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<String>,

    /// An XML signature that authenticates the containing element and its
    /// contents,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,

    /// The primary content of the element is either a sequence of one or more
    /// role descriptor elements, or a specialized descriptor that defines an
    /// affiliation.
    ///
    /// FIXME: The way this exists within the structure doesn't match how
    /// it's specified because this is only allowed if there aren't any other
    /// roles present.
    #[serde(rename = "AffiliationDescriptor")]
    pub affiliation_descriptors: Option<AffiliationDescriptor>,

    #[serde(rename = "RoleDescriptor")]
    pub role_descriptors: Option<Vec<RoleDescriptor>>,

    #[serde(rename = "IDPSSODescriptor")]
    pub idp_sso_descriptors: Option<Vec<IdpSsoDescriptor>>,

    #[serde(rename = "SPSSODescriptor")]
    pub sp_sso_descriptors: Option<Vec<SpSsoDescriptor>>,

    #[serde(rename = "AuthnAuthorityDescriptor")]
    pub authn_authority_descriptors: Option<Vec<AuthnAuthorityDescriptors>>,

    #[serde(rename = "AttributeAuthorityDescriptor")]
    pub attribute_authority_descriptors: Option<Vec<AttributeAuthorityDescriptors>>,

    #[serde(rename = "PDPDescriptor")]
    pub pdp_descriptors: Option<Vec<PdpDescriptors>>,

    /// Optional element identifying the organization responsible for the SAML
    /// entity described by the element.
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,

    /// Optional sequence of elements identifying various kinds of contact
    /// personnel.
    #[serde(rename = "ContactPerson")]
    pub contact_person: Option<Vec<ContactPerson>>,
    // **NOTE** We are missing this from the definition.
    // <AdditionalMetadataLocation> [Zero or More] Optional sequence of
    // namespace-qualified locations where additional metadata exists for the
    // SAML entity. This may include metadata in alternate formats or describing
    // adherence to other non-SAML specifications. pub
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to deserialize SAML response: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },
}

impl FromStr for EntityDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl EntityDescriptor {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root_name = "md:EntityDescriptor";
        let mut root = BytesStart::new(root_name);
        if let Some(entity_id) = &self.entity_id {
            root.push_attribute(("entityID", entity_id.as_ref()))
        }
        if let Some(valid_until) = &self.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ))
        }
        if let Some(cache_duration) = &self.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.as_ref()));
        }

        root.push_attribute(("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata"));
        root.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        root.push_attribute(("xmlns:mdrpi", "urn:oasis:names:tc:SAML:metadata:rpi"));
        root.push_attribute(("xmlns:mdattr", "urn:oasis:names:tc:SAML:metadata:attribute"));
        root.push_attribute(("xmlns:mdui", "urn:oasis:names:tc:SAML:metadata:ui"));
        root.push_attribute((
            "xmlns:idpdisc",
            "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
        ));
        root.push_attribute(("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));
        writer.write_event(Event::Start(root))?;
        for descriptor in self.sp_sso_descriptors.as_ref().unwrap_or(&vec![]) {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        for descriptor in self.idp_sso_descriptors.as_ref().unwrap_or(&vec![]) {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(organization) = &self.organization {
            let event: Event<'_> = organization.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(contact_persons) = &self.contact_person {
            for contact_person in contact_persons {
                let event: Event<'_> = contact_person.try_into()?;
                writer.write_event(event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(root_name)))?;

        Ok(String::from_utf8(write_buf)?)
    }
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
        println!("{}", &input_xml);
        let entity_descriptor: EntityDescriptor = input_xml
            .parse()
            .expect("Failed to parse sp_metadata.xml into an EntityDescriptor");
        let output_xml = entity_descriptor
            .to_xml()
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
        let output_xml = entity_descriptor
            .to_xml()
            .expect("Failed to convert EntityDescriptor to xml");
        let reparsed_entity_descriptor: EntityDescriptor = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptor");

        assert_eq!(reparsed_entity_descriptor, entity_descriptor);
    }
}
