use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedCipherData {
    #[serde(rename = "CipherValue")]
    pub value: EncryptedCipherValue,
}

impl EncryptedCipherData {
    fn name() -> &'static str {
        "xenc:CipherData"
    }
}

impl TryFrom<&EncryptedCipherData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedCipherData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(EncryptedCipherData::name());

        // Attaching namespace attributes
        root.push_attribute(("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"));
        root.push_attribute(("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"));
        root.push_attribute(("Type", "http://www.w3.org/2001/04/xmlenc#Element"));

        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.value).try_into()?;
        writer.write_event(event)?;
        writer.write_event(Event::End(BytesEnd::new(EncryptedCipherData::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
