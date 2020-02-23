use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const ATTRIBUTE_VALUE_NAME: &str = "saml2:AttributeValue";

#[derive(Clone, Debug, Deserialize)]
pub struct AttributeValue {
    #[serde(rename = "type")]
    pub attribute_type: Option<String>,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl AttributeValue {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root =
            BytesStart::borrowed(ATTRIBUTE_VALUE_NAME.as_bytes(), ATTRIBUTE_VALUE_NAME.len());
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::borrowed(
            ATTRIBUTE_VALUE_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize)]
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
