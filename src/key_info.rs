use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

use crate::ToXml;

const NAME: &str = "ds:KeyInfo";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyInfo {
    #[serde(rename = "Id")]
    pub id: Option<String>,
    #[serde(rename = "X509Data")]
    pub x509_data: Option<X509Data>,
}

impl ToXml for KeyInfo {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        self.x509_data.to_xml(writer)?;
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}

const X509_DATA_NAME: &str = "ds:X509Data";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    pub certificates: Vec<String>,
}

impl ToXml for X509Data {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let root = BytesStart::borrowed(X509_DATA_NAME.as_bytes(), X509_DATA_NAME.len());
        writer.write_event(Event::Start(root))?;

        for certificate in &self.certificates {
            let name = "ds:X509Certificate";
            writer.write_event(Event::Start(BytesStart::borrowed(
                name.as_bytes(),
                name.len(),
            )))?;
            writer.write_event(Event::Text(BytesText::from_plain_str(certificate.as_str())))?;
            writer.write_event(Event::End(BytesEnd::borrowed(name.as_bytes())))?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(X509_DATA_NAME.as_bytes())))?;
        Ok(())
    }
}
