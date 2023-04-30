use crate::metadata::helpers::write_plain_element;
use crate::metadata::{
    AttributeConsumingService, ContactPerson, Endpoint, IndexedEndpoint, KeyDescriptor,
    Organization,
};
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:SPSSODescriptor";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SpSsoDescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
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
    #[serde(rename = "@AuthnRequestsSigned")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "@WantAssertionsSigned")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "AssertionConsumerService")]
    pub assertion_consumer_services: Vec<IndexedEndpoint>,
    #[serde(rename = "AttributeConsumingService")]
    pub attribute_consuming_services: Option<Vec<AttributeConsumingService>>,
}

impl TryFrom<SpSsoDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SpSsoDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SpSsoDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SpSsoDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);

        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()));
        }

        if let Some(valid_until) = &value.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }

        if let Some(cache_duration) = &value.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.to_string().as_ref()));
        }

        if let Some(protocol_support_enumeration) = &value.protocol_support_enumeration {
            root.push_attribute((
                "protocolSupportEnumeration",
                protocol_support_enumeration.as_ref(),
            ));
        }

        if let Some(error_url) = &value.error_url {
            root.push_attribute(("errorURL", error_url.as_ref()));
        }

        if let Some(want_assertions_signed) = &value.want_assertions_signed {
            root.push_attribute((
                "WantAssertionsSigned",
                want_assertions_signed.to_string().as_ref(),
            ));
        }

        if let Some(authn_requests_signed) = &value.authn_requests_signed {
            root.push_attribute((
                "AuthnRequestsSigned",
                authn_requests_signed.to_string().as_ref(),
            ));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(key_descriptors) = &value.key_descriptors {
            for descriptor in key_descriptors {
                let event: Event<'_> = descriptor.try_into()?;
                writer.write_event(event)?;
            }
        }

        if let Some(organization) = &value.organization {
            let event: Event<'_> = organization.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(contact_people) = &value.contact_people {
            for contact in contact_people {
                let event: Event<'_> = contact.try_into()?;
                writer.write_event(event)?;
            }
        }

        if let Some(artifact_resolution_service) = &value.artifact_resolution_service {
            for service in artifact_resolution_service {
                writer.write_event(service.to_xml("md:ArtifactResolutionService")?)?;
            }
        }

        if let Some(single_logout_services) = &value.single_logout_services {
            for service in single_logout_services {
                writer.write_event(service.to_xml("md:SingleLogoutService")?)?;
            }
        }

        if let Some(manage_name_id_services) = &value.manage_name_id_services {
            for service in manage_name_id_services {
                writer.write_event(service.to_xml("md:ManageNameIDService")?)?;
            }
        }

        if let Some(name_id_formats) = &value.name_id_formats {
            for format in name_id_formats {
                write_plain_element(&mut writer, "md:NameIDFormat", format.as_ref())?;
            }
        }

        for service in &value.assertion_consumer_services {
            writer.write_event(service.to_xml("md:AssertionConsumerService")?)?;
        }

        if let Some(attribute_consuming_services) = &value.attribute_consuming_services {
            for service in attribute_consuming_services {
                let event: Event<'_> = service.try_into()?;
                writer.write_event(event)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
