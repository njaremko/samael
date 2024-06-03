use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

impl EncryptionMethod {
    fn name() -> &'static str {
        "xenc:EncryptionMethod"
    }
}

impl TryFrom<&EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptionMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(EncryptionMethod::name());

        root.push_attribute(("Algorithm", value.algorithm.as_str()));

        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
