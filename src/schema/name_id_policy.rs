use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2p:NameIDPolicy";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(default, setter(into, strip_option))]
pub struct NameIdPolicy {
    #[serde(rename = "@Format")]
    pub format: Option<String>,
    #[serde(rename = "@SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "@AllowCreate")]
    pub allow_create: Option<bool>,
}

impl TryFrom<NameIdPolicy> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: NameIdPolicy) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&NameIdPolicy> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &NameIdPolicy) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(format) = &value.format {
            root.push_attribute(("Format", format.as_ref()));
        }
        if let Some(sp_name_qualifier) = &value.sp_name_qualifier {
            root.push_attribute(("SPNameQualifier", sp_name_qualifier.as_ref()));
        }
        if let Some(allow_create) = &value.allow_create {
            root.push_attribute(("AllowCreate", allow_create.to_string().as_ref()));
        }
        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
