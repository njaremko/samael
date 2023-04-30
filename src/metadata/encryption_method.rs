use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:EncryptionMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

impl TryFrom<EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptionMethod) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptionMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);

        root.push_attribute(("Algorithm", value.algorithm.as_ref()));

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
