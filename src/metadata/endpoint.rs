use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Endpoint {
    #[serde(rename = "Binding")]
    pub binding: String,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "ResponseLocation")]
    pub response_location: Option<String>,
}

impl Endpoint {
    pub fn to_xml(&self, element_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(element_name.as_bytes(), element_name.len());
        root.push_attribute(("Binding", self.binding.as_ref()));
        root.push_attribute(("Location", self.location.as_ref()));
        if let Some(response_location) = &self.response_location {
            root.push_attribute(("ResponseLocation", response_location.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::borrowed(element_name.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct IndexedEndpoint {
    #[serde(rename = "Binding")]
    pub binding: String,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "ResponseLocation")]
    pub response_location: Option<String>,
    pub index: usize,
    #[serde(rename = "isDefault")]
    pub is_default: Option<bool>,
}

impl IndexedEndpoint {
    pub fn to_xml(&self, element_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(element_name.as_bytes(), element_name.len());
        root.push_attribute(("Binding", self.binding.as_ref()));
        root.push_attribute(("Location", self.location.as_ref()));
        root.push_attribute(("index", self.index.to_string().as_ref()));
        if let Some(response_location) = &self.response_location {
            root.push_attribute(("ResponseLocation", response_location.as_ref()));
        }
        if let Some(is_default) = &self.is_default {
            root.push_attribute(("isDefault", is_default.to_string().as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::borrowed(element_name.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
