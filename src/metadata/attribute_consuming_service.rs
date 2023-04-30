use crate::attribute::AttributeValue;
use crate::metadata::LocalizedName;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:AttributeConsumingService";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeConsumingService {
    #[serde(rename = "@index")]
    pub index: usize,
    #[serde(rename = "@isDefault")]
    pub is_default: Option<bool>,
    #[serde(rename = "ServiceName", default)]
    pub service_names: Vec<LocalizedName>,
    #[serde(rename = "ServiceDescription")]
    pub service_descriptions: Option<Vec<LocalizedName>>,
    #[serde(rename = "RequestedAttribute", default)]
    pub request_attributes: Vec<RequestedAttribute>,
}

impl TryFrom<AttributeConsumingService> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AttributeConsumingService) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AttributeConsumingService> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AttributeConsumingService) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);

        root.push_attribute(("index", value.index.to_string().as_ref()));
        if let Some(is_default) = &value.is_default {
            root.push_attribute(("isDefault", is_default.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        for name in &value.service_names {
            writer.write_event(name.to_xml("md:ServiceName")?)?;
        }

        if let Some(service_descriptions) = &value.service_descriptions {
            for name in service_descriptions {
                writer.write_event(name.to_xml("md:ServiceDescription")?)?;
            }
        }
        for request_attributes in &value.request_attributes {
            let event: Event<'_> = request_attributes.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const REQUESTED_ATTRIBUTE_NAME: &str = "md:RequestedAttribute";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedAttribute {
    #[serde(rename = "@FriendlyName")]
    pub friendly_name: Option<String>,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@NameFormat")]
    pub name_format: Option<String>,
    #[serde(rename = "AttributeValue")]
    pub values: Option<Vec<AttributeValue>>,
    #[serde(rename = "@isRequired")]
    pub is_required: Option<bool>,
}

impl TryFrom<RequestedAttribute> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: RequestedAttribute) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&RequestedAttribute> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RequestedAttribute) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(REQUESTED_ATTRIBUTE_NAME);
        root.push_attribute(("Name", value.name.as_ref()));
        if let Some(name_format) = &value.name_format {
            root.push_attribute(("NameFormat", name_format.as_ref()));
        }
        if let Some(friendly_name) = &value.friendly_name {
            root.push_attribute(("FriendlyName", friendly_name.as_ref()));
        }
        if let Some(is_required) = &value.is_required {
            root.push_attribute(("isRequired", is_required.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(values) = &value.values {
            for value in values {
                let event: Event<'_> = value.try_into()?;
                writer.write_event(event)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(REQUESTED_ATTRIBUTE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
