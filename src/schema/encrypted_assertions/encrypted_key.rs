use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedKey {
    #[serde(rename = "EncryptionMethod")]
    pub method: EncryptionMethod,
    #[serde(rename = "CipherData")]
    pub encryption_cipher_data: EncryptedCipherData,
}

impl EncryptedKey {
    fn name() -> &'static str {
        "xenc:EncryptedKey"
    }
}

impl TryFrom<&EncryptedKey> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedKey) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(EncryptedKey::name());

        writer.write_event(Event::Start(root))?;
        let encryption_event: Event<'_> = (&value.method).try_into()?;
        writer.write_event(encryption_event)?;
        let event_data: Event<'_> = (&value.encryption_cipher_data).try_into()?;
        writer.write_event(event_data)?;
        writer.write_event(Event::End(BytesEnd::new(EncryptedKey::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
