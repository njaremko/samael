use crate::attribute::AttributeValue;
use crate::metadata::LocalizedName;
use crate::ToXml;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

const NAME: &str = "md:AttributeConsumingService";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeConsumingService {
    pub index: usize,
    #[serde(rename = "isDefault")]
    pub is_default: Option<bool>,
    #[serde(rename = "ServiceName", default)]
    pub service_names: Vec<LocalizedName>,
    #[serde(rename = "ServiceDescription")]
    pub service_descriptions: Option<Vec<LocalizedName>>,
    #[serde(rename = "RequestedAttribute", default)]
    pub request_attributes: Vec<RequestedAttribute>,
}

impl ToXml for AttributeConsumingService {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());

        root.push_attribute(("index", self.index.to_string().as_ref()));
        if let Some(is_default) = &self.is_default {
            root.push_attribute(("isDefault", is_default.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        for name in &self.service_names {
            name.to_xml(writer, "md:ServiceName")?;
        }
        if let Some(service_descriptions) = &self.service_descriptions {
            for name in service_descriptions {
                name.to_xml(writer, "md:ServiceDescription")?;
            }
        }
        self.request_attributes.to_xml(writer)?;

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}

const REQUESTED_ATTRIBUTE_NAME: &str = "md:RequestedAttribute";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedAttribute {
    #[serde(rename = "FriendlyName")]
    pub friendly_name: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NameFormat")]
    pub name_format: Option<String>,
    #[serde(rename = "AttributeValue")]
    pub values: Option<Vec<AttributeValue>>,
    #[serde(rename = "isRequired")]
    pub is_required: Option<bool>,
}

impl ToXml for RequestedAttribute {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(
            REQUESTED_ATTRIBUTE_NAME.as_bytes(),
            REQUESTED_ATTRIBUTE_NAME.len(),
        );
        root.push_attribute(("Name", self.name.as_ref()));
        if let Some(name_format) = &self.name_format {
            root.push_attribute(("NameFormat", name_format.as_ref()));
        }
        if let Some(friendly_name) = &self.friendly_name {
            root.push_attribute(("FriendlyName", friendly_name.as_ref()));
        }
        if let Some(is_required) = &self.is_required {
            root.push_attribute(("isRequired", is_required.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        self.values.to_xml(writer)?;
        writer.write_event(Event::End(BytesEnd::borrowed(
            REQUESTED_ATTRIBUTE_NAME.as_bytes(),
        )))?;
        Ok(())
    }
}
