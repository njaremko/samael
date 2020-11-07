use crate::metadata::helpers::write_plain_element;
use crate::metadata::{
    AttributeConsumingService, ContactPerson, Endpoint, IndexedEndpoint, KeyDescriptor,
    Organization,
};
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:SPSSODescriptor";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SpSsoDescriptor {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "KeyDescriptor")]
    pub key_descriptors: Option<Vec<KeyDescriptor>>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson")]
    pub contact_people: Option<Vec<ContactPerson>>,
    #[serde(rename = "ArtifactResolutionService")]
    pub artifact_resolution_service: Option<Vec<IndexedEndpoint>>,
    #[serde(rename = "SingleLogoutService")]
    pub single_logout_services: Option<Vec<Endpoint>>,
    #[serde(rename = "ManageNameIDService")]
    pub manage_name_id_services: Option<Vec<Endpoint>>,
    #[serde(rename = "NameIDFormat")]
    pub name_id_formats: Option<Vec<String>>,
    // ^-SSODescriptor
    #[serde(rename = "AuthnRequestsSigned")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "WantAssertionsSigned")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "AssertionConsumerService")]
    pub assertion_consumer_services: Vec<IndexedEndpoint>,
    #[serde(rename = "AttributeConsumingService")]
    pub attribute_consuming_services: Option<Vec<AttributeConsumingService>>,
}

impl SpSsoDescriptor {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());

        if let Some(id) = &self.id {
            root.push_attribute(("ID", id.as_ref()));
        }

        if let Some(valid_until) = &self.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }

        if let Some(cache_duration) = &self.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.to_string().as_ref()));
        }

        if let Some(protocol_support_enumeration) = &self.protocol_support_enumeration {
            root.push_attribute((
                "protocolSupportEnumeration",
                protocol_support_enumeration.as_ref(),
            ));
        }

        if let Some(error_url) = &self.error_url {
            root.push_attribute(("errorURL", error_url.as_ref()));
        }

        if let Some(want_assertions_signed) = &self.want_assertions_signed {
            root.push_attribute((
                "WantAssertionsSigned",
                want_assertions_signed.to_string().as_ref(),
            ));
        }

        if let Some(authn_requests_signed) = &self.authn_requests_signed {
            root.push_attribute((
                "AuthnRequestsSigned",
                authn_requests_signed.to_string().as_ref(),
            ));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(key_descriptors) = &self.key_descriptors {
            for descriptor in key_descriptors {
                writer.write(descriptor.to_xml()?.as_bytes())?;
            }
        }

        if let Some(organization) = &self.organization {
            writer.write(organization.to_xml()?.as_bytes())?;
        }

        if let Some(contact_people) = &self.contact_people {
            for contact in contact_people {
                writer.write(contact.to_xml()?.as_bytes())?;
            }
        }

        if let Some(artifact_resolution_service) = &self.artifact_resolution_service {
            for service in artifact_resolution_service {
                writer.write(service.to_xml("md:ArtifactResolutionService")?.as_bytes())?;
            }
        }

        if let Some(single_logout_services) = &self.single_logout_services {
            for service in single_logout_services {
                writer.write(service.to_xml("md:SingleLogoutService")?.as_bytes())?;
            }
        }

        if let Some(manage_name_id_services) = &self.manage_name_id_services {
            for service in manage_name_id_services {
                writer.write(service.to_xml("md:ManageNameIDService")?.as_bytes())?;
            }
        }

        if let Some(name_id_formats) = &self.name_id_formats {
            for format in name_id_formats {
                write_plain_element(&mut writer, "md:NameIDFormat", format.as_ref())?;
            }
        }

        for service in &self.assertion_consumer_services {
            writer.write(service.to_xml("md:AssertionConsumerService")?.as_bytes())?;
        }

        if let Some(attribute_consuming_services) = &self.attribute_consuming_services {
            for service in attribute_consuming_services {
                writer.write(service.to_xml()?.as_bytes())?;
            }
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
