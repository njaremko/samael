use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2:Issuer";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into, strip_option))]
pub struct Issuer {
    #[serde(rename = "@NameQualifier")]
    pub name_qualifier: Option<String>,
    #[serde(rename = "@SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "@Format")]
    pub format: Option<String>,
    #[serde(rename = "@SPProvidedID")]
    pub sp_provided_id: Option<String>,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl TryFrom<Issuer> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Issuer) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Issuer> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Issuer) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        root.push_attribute(SCHEMA);

        if let Some(name_qualifier) = &value.name_qualifier {
            root.push_attribute(("NameQualifier", name_qualifier.as_ref()));
        }
        if let Some(sp_name_qualifier) = &value.sp_name_qualifier {
            root.push_attribute(("SPNameQualifier", sp_name_qualifier.as_ref()));
        }
        if let Some(format) = &value.format {
            root.push_attribute(("Format", format.as_ref()));
        }
        if let Some(sp_provided_id) = &value.sp_provided_id {
            root.push_attribute(("SPProvidedID", sp_provided_id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(value) = &value.value {
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
