use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedCipherValue {
    #[serde(rename = "$value")]
    pub value: String,
}

impl EncryptedCipherValue {
    fn name() -> &'static str {
        "xenc:CipherValue"
    }
}

impl TryFrom<&EncryptedCipherValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedCipherValue) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(EncryptedCipherValue::name());
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(EncryptedCipherValue::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
