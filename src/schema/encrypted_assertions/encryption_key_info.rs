use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptionKeyInfo {
    #[serde(rename = "EncryptedKey")]
    pub encrypted_key: EncryptedKey,
}

impl EncryptionKeyInfo {
    fn name() -> &'static str {
        "dsig:KeyInfo"
    }
}

impl TryFrom<&EncryptionKeyInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptionKeyInfo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(EncryptionKeyInfo::name());

        root.push_attribute(("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"));

        writer.write_event(Event::Start(root))?;
        let encrypted_key_event: Event<'_> = (&value.encrypted_key).try_into()?;
        writer.write_event(encrypted_key_event)?;
        writer.write_event(Event::End(BytesEnd::new(EncryptionKeyInfo::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
