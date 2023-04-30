use crate::key_info::KeyInfo;
use crate::metadata::EncryptionMethod;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:KeyDescriptor";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyDescriptor {
    #[serde(rename = "@use")]
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

impl TryFrom<KeyDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: KeyDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&KeyDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &KeyDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(key_use) = &value.key_use {
            root.push_attribute(("use", key_use.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        let event: Event<'_> = (&value.key_info).try_into()?;
        writer.write_event(event)?;

        if let Some(encryption_methods) = &value.encryption_methods {
            for method in encryption_methods {
                let event: Event<'_> = method.try_into()?;
                writer.write_event(event)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
