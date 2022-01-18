use quick_xml::events::{BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

use crate::ToXml;

const NAME: &str = "saml2p:NameIDPolicy";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct NameIdPolicy {
    #[serde(rename = "Format")]
    pub format: Option<String>,
    #[serde(rename = "SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "AllowCreate")]
    pub allow_create: Option<bool>,
}

impl ToXml for NameIdPolicy {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(format) = &self.format {
            root.push_attribute(("Format", format.as_ref()));
        }
        if let Some(sp_name_qualifier) = &self.sp_name_qualifier {
            root.push_attribute(("SPNameQualifier", sp_name_qualifier.as_ref()));
        }
        if let Some(allow_create) = &self.allow_create {
            root.push_attribute(("AllowCreate", allow_create.to_string().as_ref()));
        }
        writer.write_event(Event::Empty(root))?;
        Ok(())
    }
}
