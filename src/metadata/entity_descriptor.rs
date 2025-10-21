use crate::metadata::{
    AffiliationDescriptor, AttributeAuthorityDescriptors, AuthnAuthorityDescriptors, ContactPerson,
    IdpSsoDescriptor, Organization, PdpDescriptors, RoleDescriptor, SpSsoDescriptor,
};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::collections::VecDeque;
use std::io::Cursor;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to deserialize SAML response: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum EntityDescriptorType {
    #[serde(rename = "EntitiesDescriptor")]
    EntitiesDescriptor(EntitiesDescriptor),
    #[serde(rename = "EntityDescriptor")]
    EntityDescriptor(EntityDescriptor),
}

impl EntityDescriptorType {
    pub fn iter(&self) -> EntityDescriptorIterator {
        EntityDescriptorIterator::new(self)
    }
}

impl FromStr for EntityDescriptorType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<EntityDescriptorType> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EntityDescriptorType) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EntityDescriptorType> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EntityDescriptorType) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let event: Event<'_> = match value {
            EntityDescriptorType::EntitiesDescriptor(descriptor) => descriptor.try_into()?,
            EntityDescriptorType::EntityDescriptor(descriptor) => descriptor.try_into()?,
        };
        writer.write_event(event)?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const ENTITIES_DESCRIPTOR_NAME: &str = "md:EntitiesDescriptor";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename = "md:EntitiesDescriptor")]
pub struct EntitiesDescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(default, rename = "$value")]
    pub descriptors: Vec<EntityDescriptorType>,
}

impl FromStr for EntitiesDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<EntitiesDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EntitiesDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EntitiesDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EntitiesDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(ENTITIES_DESCRIPTOR_NAME);
        root.push_attribute(("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata"));
        root.push_attribute((
            "xmlns:alg",
            "urn:oasis:names:tc:SAML:2.0:metadata:algsupport",
        ));
        root.push_attribute(("xmlns:mdui", "urn:oasis:names:tc:SAML:metadata:ui"));
        root.push_attribute(("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));

        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()))
        }

        if let Some(name) = &value.name {
            root.push_attribute(("Name", name.as_ref()))
        }

        if let Some(valid_until) = &value.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ))
        }

        if let Some(cache_duration) = &value.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        for descriptor in &value.descriptors {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(ENTITIES_DESCRIPTOR_NAME)))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const ENTITY_DESCRIPTOR_NAME: &str = "md:EntityDescriptor";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename = "md:EntityDescriptor")]
pub struct EntityDescriptor {
    #[serde(rename = "@entityID")]
    pub entity_id: Option<String>,
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<String>,
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
    #[serde(rename = "AffiliationDescriptor")]
    pub affiliation_descriptors: Option<AffiliationDescriptor>,
    #[serde(rename = "ContactPerson")]
    pub contact_person: Option<Vec<ContactPerson>>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
}

impl FromStr for EntityDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<EntityDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EntityDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EntityDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EntityDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(ENTITY_DESCRIPTOR_NAME);
        root.push_attribute(("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata"));
        root.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        root.push_attribute(("xmlns:mdrpi", "urn:oasis:names:tc:SAML:metadata:rpi"));
        root.push_attribute(("xmlns:mdattr", "urn:oasis:names:tc:SAML:metadata:attribute"));
        root.push_attribute(("xmlns:mdui", "urn:oasis:names:tc:SAML:metadata:ui"));
        root.push_attribute(("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));
        root.push_attribute((
            "xmlns:idpdisc",
            "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
        ));

        if let Some(entity_id) = &value.entity_id {
            root.push_attribute(("entityID", entity_id.as_ref()))
        }
        if let Some(valid_until) = &value.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ))
        }
        if let Some(cache_duration) = &value.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        for descriptor in value.sp_sso_descriptors.as_ref().unwrap_or(&vec![]) {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        for descriptor in value.idp_sso_descriptors.as_ref().unwrap_or(&vec![]) {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(organization) = &value.organization {
            let event: Event<'_> = organization.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(contact_persons) = &value.contact_person {
            for contact_person in contact_persons {
                let event: Event<'_> = contact_person.try_into()?;
                writer.write_event(event)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(ENTITY_DESCRIPTOR_NAME)))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone)]
pub struct EntityDescriptorIterator<'a> {
    queue: VecDeque<&'a EntityDescriptorType>,
}

impl<'a> EntityDescriptorIterator<'a> {
    pub fn new(root: &'a EntityDescriptorType) -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(root);
        EntityDescriptorIterator { queue }
    }
}

impl<'a> Iterator for EntityDescriptorIterator<'a> {
    type Item = &'a EntityDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(current) = self.queue.pop_front() {
            match current {
                EntityDescriptorType::EntitiesDescriptor(entities_descriptor) => {
                    for descriptor in &entities_descriptor.descriptors {
                        self.queue.push_back(descriptor);
                    }
                }
                EntityDescriptorType::EntityDescriptor(entity_descriptor) => {
                    return Some(entity_descriptor);
                }
            }
        }
        None
    }
}

impl EntityDescriptor {
    pub fn sso_binding_location(&self, binding: &str) -> Option<String> {
        if let Some(idp_sso_descriptors) = &self.idp_sso_descriptors {
            for idp_sso_descriptor in idp_sso_descriptors {
                return idp_sso_descriptor.sso_binding_location(binding);
            }
        }
        None
    }

    pub fn slo_binding_location(&self, binding: &str) -> Option<String> {
        if let Some(idp_sso_descriptors) = &self.idp_sso_descriptors {
            for idp_sso_descriptor in idp_sso_descriptors {
                return idp_sso_descriptor.slo_binding_location(binding);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use crate::traits::ToXml;

    use super::{EntitiesDescriptor, EntityDescriptor, EntityDescriptorType};

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
            .to_string()
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
            .expect("Failed to parse idp_metadata.xml into an EntityDescriptor");
        let output_xml = entity_descriptor
            .to_string()
            .expect("Failed to convert EntityDescriptor to xml");
        let reparsed_entity_descriptor: EntityDescriptor = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptor");

        assert_eq!(reparsed_entity_descriptor, entity_descriptor);
    }

    #[test]
    fn test_idp_entities_descriptor() {
        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_metadata_nested.xml"
        ));
        let entities_descriptor: EntitiesDescriptor = input_xml
            .parse()
            .expect("Failed to parse idp_metadata_nested.xml into an EntitiesDescriptor");
        let output_xml = entities_descriptor
            .to_string()
            .expect("Failed to convert EntitiesDescriptor to xml");
        let reparsed_entities_descriptor: EntitiesDescriptor = output_xml
            .parse()
            .expect("Failed to parse EntitiesDescriptor");

        assert_eq!(2, reparsed_entities_descriptor.descriptors.len());
        assert_eq!(reparsed_entities_descriptor, entities_descriptor);
    }

    #[test]
    fn test_idp_entity_descriptor_type() {
        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_metadata.xml"
        ));
        let entity_descriptor_type: EntityDescriptorType = input_xml
            .parse()
            .expect("Failed to parse idp_metadata.xml into an EntityDescriptorType");
        let output_xml = entity_descriptor_type
            .to_string()
            .expect("Failed to convert EntityDescriptorType to xml");
        let reparsed_entity_descriptor_type: EntityDescriptorType = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptorType");

        assert_eq!(reparsed_entity_descriptor_type, entity_descriptor_type);

        let expected_entity_descriptor: EntityDescriptor = input_xml
            .parse()
            .expect("Failed to parse idp_metadata.xml into an EntityDescriptor");
        let entity_descriptor = entity_descriptor_type
            .iter()
            .next()
            .expect("Failed to take first EntityDescriptor from EntityDescriptorType");

        assert_eq!(&expected_entity_descriptor, entity_descriptor);
    }

    #[test]
    fn test_idp_entity_descriptor_type_nested() {
        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_metadata_nested.xml"
        ));
        let entity_descriptor_type: EntityDescriptorType = input_xml
            .parse()
            .expect("Failed to parse idp_metadata_nested.xml into an EntityDescriptorType");
        let output_xml = entity_descriptor_type
            .to_string()
            .expect("Failed to convert EntityDescriptorType to xml");
        let reparsed_entity_descriptor_type: EntityDescriptorType = output_xml
            .parse()
            .expect("Failed to parse EntityDescriptorType");

        assert_eq!(reparsed_entity_descriptor_type, entity_descriptor_type);

        let input_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_metadata.xml"
        ));
        let expected_entity_descriptor: EntityDescriptor = input_xml
            .parse()
            .expect("Failed to parse idp_metadata.xml into an EntityDescriptor");
        let entity_descriptor = entity_descriptor_type
            .iter()
            .next()
            .expect("Failed to take first EntityDescriptor from EntityDescriptorType");
        println!("{entity_descriptor:#?}");

        assert_eq!(&expected_entity_descriptor, entity_descriptor);
    }
}
