use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:EncryptionMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

impl EncryptionMethod {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());

        root.push_attribute(("Algorithm", self.algorithm.as_ref()));

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
