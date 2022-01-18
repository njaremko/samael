use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedName {
    #[serde(rename = "xml:lang")]
    pub lang: String,
    #[serde(rename = "$value")]
    pub value: String,
}

impl LocalizedName {
    pub fn to_xml<W: Write>(
        &self,
        writer: &mut Writer<W>,
        element_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(element_name.as_bytes(), element_name.len());
        root.push_attribute(("xml:lang", self.lang.as_ref()));
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_plain_str(&self.value)))?;
        writer.write_event(Event::End(BytesEnd::borrowed(element_name.as_bytes())))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedUri {
    #[serde(rename = "xml:lang")]
    pub lang: String,
    #[serde(rename = "$value")]
    pub value: String,
}

impl LocalizedUri {
    pub fn to_xml<W: Write>(
        &self,
        writer: &mut Writer<W>,
        element_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(element_name.as_bytes(), element_name.len());
        root.push_attribute(("xml:lang", self.lang.as_ref()));
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_plain_str(&self.value)))?;
        writer.write_event(Event::End(BytesEnd::borrowed(element_name.as_bytes())))?;
        Ok(())
    }
}
