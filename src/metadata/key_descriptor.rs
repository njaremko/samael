use crate::key_info::KeyInfo;
use crate::metadata::EncryptionMethod;
use crate::ToXml;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

const NAME: &str = "md:KeyDescriptor";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyDescriptor {
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,
    #[serde(rename = "EncryptionMethod")]
    pub encryption_methods: Option<Vec<EncryptionMethod>>,
}

impl KeyDescriptor {
    pub fn is_signing(&self) -> bool {
        self.key_use
            .as_ref()
            .map(|u| u == "signing")
            .unwrap_or(false)
    }
}

impl ToXml for KeyDescriptor {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(key_use) = &self.key_use {
            root.push_attribute(("use", key_use.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        self.key_info.to_xml(writer)?;
        self.encryption_methods.to_xml(writer)?;
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}
