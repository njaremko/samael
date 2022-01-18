use crate::metadata::{
    AffiliationDescriptor, AttributeAuthorityDescriptors, AuthnAuthorityDescriptors, ContactPerson,
    IdpSsoDescriptor, Organization, PdpDescriptors, RoleDescriptor, SpSsoDescriptor,
};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use snafu::Snafu;
use std::io::Cursor;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename = "md:EntityDescriptor")]
pub struct EntityDescriptor {
    #[serde(rename = "entityID")]
    pub entity_id: Option<String>,
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
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

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize SAML response: {:?}", source))]
    #[snafu(context(false))]
    ParseError { source: quick_xml::DeError },
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
        let mut root = BytesStart::borrowed(root_name.as_bytes(), root_name.len());
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
            writer.write(descriptor.to_xml()?.as_bytes())?;
        }

        for descriptor in self.idp_sso_descriptors.as_ref().unwrap_or(&vec![]) {
            writer.write(descriptor.to_xml()?.as_bytes())?;
        }

        if let Some(organization) = &self.organization {
            writer.write(organization.to_xml()?.as_bytes())?;
        }

        if let Some(contact_persons) = &self.contact_person {
            for contact_person in contact_persons {
                writer.write(contact_person.to_xml()?.as_bytes())?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(root_name.as_bytes())))?;

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
