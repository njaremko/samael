use crate::metadata::helpers::write_plain_element;
use crate::metadata::{
    AttributeConsumingService, ContactPerson, Endpoint, IndexedEndpoint, KeyDescriptor,
    Organization,
};
use crate::ToXml;
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

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

impl ToXml for SpSsoDescriptor {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
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
        self.key_descriptors.to_xml(writer)?;
        self.organization.to_xml(writer)?;
        self.contact_people.to_xml(writer)?;
        if let Some(artifact_resolution_service) = &self.artifact_resolution_service {
            for service in artifact_resolution_service {
                service.to_xml(writer, "md:ArtifactResolutionService")?;
            }
        }
        if let Some(single_logout_services) = &self.single_logout_services {
            for service in single_logout_services {
                service.to_xml(writer, "md:SingleLogoutService")?;
            }
        }
        if let Some(manage_name_id_services) = &self.manage_name_id_services {
            for service in manage_name_id_services {
                service.to_xml(writer, "md:ManageNameIDService")?;
            }
        }
        if let Some(name_id_formats) = &self.name_id_formats {
            for format in name_id_formats {
                write_plain_element(writer, "md:NameIDFormat", format.as_ref())?;
            }
        }
        for service in &self.assertion_consumer_services {
            service.to_xml(writer, "md:AssertionConsumerService")?;
        }
        self.attribute_consuming_services.to_xml(writer)?;
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}
