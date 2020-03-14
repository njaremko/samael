use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const ATTRIBUTE_VALUE_NAME: &str = "saml2:AttributeValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeValue {
    #[serde(rename = "xsi:type")]
    pub attribute_type: Option<String>,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl AttributeValue {
    fn schema() -> Vec<(&'static str, &'static str)> {
        vec![
            ("xmlns:xs", "http://www.w3.org/2001/XMLSchema"),
            ("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
        ]
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root =
            BytesStart::borrowed(ATTRIBUTE_VALUE_NAME.as_bytes(), ATTRIBUTE_VALUE_NAME.len());

        for attr in Self::schema() {
            root.push_attribute(attr);
        }

        if let Some(typ) = &self.attribute_type {
            root.push_attribute(("xsi:type", typ.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(value) = &self.value {
            writer.write(value.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(
            ATTRIBUTE_VALUE_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Attribute {
    #[serde(rename = "FriendlyName")]
    pub friendly_name: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "NameFormat")]
    pub name_format: Option<String>,
    #[serde(rename = "AttributeValue", default)]
    pub values: Vec<AttributeValue>,
}

impl Attribute {
    fn name() -> &'static str {
        "saml2:Attribute"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        if let Some(name) = &self.name {
            root.push_attribute(("Name", name.as_ref()));
        }

        if let Some(format) = &self.name_format {
            root.push_attribute(("NameFormat", format.as_ref()));
        }

        if let Some(name) = &self.friendly_name {
            root.push_attribute(("FriendlyName", name.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        for val in &self.values {
            writer.write(val.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
