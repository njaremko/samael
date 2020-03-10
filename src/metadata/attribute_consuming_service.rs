use crate::attribute::AttributeValue;
use crate::metadata::LocalizedName;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

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

impl AttributeConsumingService {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());

        root.push_attribute(("index", self.index.to_string().as_ref()));
        if let Some(is_default) = &self.is_default {
            root.push_attribute(("isDefault", is_default.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        for name in &self.service_names {
            writer.write(name.to_xml("md:ServiceName")?.as_bytes())?;
        }

        if let Some(service_descriptions) = &self.service_descriptions {
            for name in service_descriptions {
                writer.write(name.to_xml("md:ServiceDescription")?.as_bytes())?;
            }
        }
        for request_attributes in &self.request_attributes {
            writer.write(request_attributes.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
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

impl RequestedAttribute {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
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

        if let Some(values) = &self.values {
            for value in values {
                writer.write(value.to_xml()?.as_bytes())?;
            }
        }

        writer.write_event(Event::End(BytesEnd::borrowed(
            REQUESTED_ATTRIBUTE_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
