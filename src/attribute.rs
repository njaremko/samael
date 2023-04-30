use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::fmt::Debug;
use std::io::Cursor;

const ATTRIBUTE_VALUE_NAME: &str = "saml2:AttributeValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeValue {
    #[serde(rename = "@xsi:type")]
    #[serde(alias = "@type")]
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
}

impl TryFrom<AttributeValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AttributeValue) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AttributeValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AttributeValue) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(ATTRIBUTE_VALUE_NAME);

        for attr in AttributeValue::schema() {
            root.push_attribute(attr);
        }

        if let Some(typ) = &value.attribute_type {
            root.push_attribute(("xsi:type", typ.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(value) = &value.value {
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
        }

        writer.write_event(Event::End(BytesEnd::new(ATTRIBUTE_VALUE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Attribute {
    #[serde(rename = "@FriendlyName")]
    pub friendly_name: Option<String>,
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "@NameFormat")]
    pub name_format: Option<String>,
    #[serde(rename = "AttributeValue", default)]
    pub values: Vec<AttributeValue>,
}

impl Attribute {
    fn name() -> &'static str {
        "saml2:Attribute"
    }
}

impl TryFrom<Attribute> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Attribute> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Attribute) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(Attribute::name());

        if let Some(name) = &value.name {
            root.push_attribute(("Name", name.as_ref()));
        }

        if let Some(format) = &value.name_format {
            root.push_attribute(("NameFormat", format.as_ref()));
        }

        if let Some(name) = &value.friendly_name {
            root.push_attribute(("FriendlyName", name.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        for val in &value.values {
            let event: Event<'_> = val.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(Attribute::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
