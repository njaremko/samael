use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2:Issuer";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Issuer {
    #[serde(rename = "NameQualifier")]
    pub name_qualifier: Option<String>,
    #[serde(rename = "SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "Format")]
    pub format: Option<String>,
    #[serde(rename = "SPProvidedID")]
    pub sp_provided_id: Option<String>,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl Issuer {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);

        if let Some(name_qualifier) = &self.name_qualifier {
            root.push_attribute(("NameQualifier", name_qualifier.as_ref()));
        }
        if let Some(sp_name_qualifier) = &self.sp_name_qualifier {
            root.push_attribute(("SPNameQualifier", sp_name_qualifier.as_ref()));
        }
        if let Some(format) = &self.format {
            root.push_attribute(("Format", format.as_ref()));
        }
        if let Some(sp_provided_id) = &self.sp_provided_id {
            root.push_attribute(("SPProvidedID", sp_provided_id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(value) = &self.value {
            writer.write_event(Event::Text(BytesText::from_plain_str(value.as_ref())))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
