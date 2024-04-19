use std::io::{Cursor, Write};

use quick_xml::{
    events::{BytesEnd, BytesStart, BytesText, Event},
    Writer,
};
use serde::Deserialize;

const NAME: &str = "saml2p:Extensions";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Extensions(pub Vec<String>);

impl TryFrom<Extensions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Extensions) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Extensions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Extensions) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::from_content(NAME, NAME.len());
        writer.write_event(Event::Start(root))?;

        for extension in &value.0 {
            writer.get_mut().write_all(extension.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToXml;

    #[test]
    fn extensions_xml_serialization() {
        assert_eq!(
            r#"<saml2p:Extensions><qqq a="b"/></saml2p:Extensions>"#,
            Extensions(vec![r#"<qqq a="b"/>"#.to_string()])
                .to_xml()
                .unwrap(),
        )
    }
}
