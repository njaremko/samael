use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedName {
    #[serde(rename = "@xml:lang")]
    #[serde(alias = "@lang")]
    pub lang: Option<String>,
    #[serde(rename = "$value")]
    pub value: String,
}

impl LocalizedName {
    pub fn to_xml(&self, element_name: &str) -> Result<Event, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(element_name);
        if let Some(x) = &self.lang {
            root.push_attribute(("xml:lang", x.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(&self.value)))?;
        writer.write_event(Event::End(BytesEnd::new(element_name)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalizedUri {
    #[serde(rename = "@xml:lang")]
    #[serde(alias = "@lang")]
    pub lang: Option<String>,
    #[serde(rename = "$value")]
    pub value: String,
}

impl LocalizedUri {
    pub fn to_xml(&self, element_name: &str) -> Result<Event, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(element_name);
        if let Some(x) = &self.lang {
            root.push_attribute(("xml:lang", x.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(&self.value)))?;
        writer.write_event(Event::End(BytesEnd::new(element_name)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
