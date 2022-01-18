use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

use crate::ToXml;

const NAME: &str = "md:EncryptionMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

impl ToXml for EncryptionMethod {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());

        root.push_attribute(("Algorithm", self.algorithm.as_ref()));

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}
