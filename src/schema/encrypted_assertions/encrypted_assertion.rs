use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedAssertion {
    #[serde(rename = "EncryptedData")]
    pub data: EncryptedData,
}

impl EncryptedAssertion {
    fn name() -> &'static str {
        "saml2:EncryptedAssertion"
    }
}

impl TryFrom<&EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedAssertion) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(EncryptedAssertion::name());

        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.data).try_into()?;
        writer.write_event(event)?;
        writer.write_event(Event::End(BytesEnd::new(EncryptedAssertion::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
