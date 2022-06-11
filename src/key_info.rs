use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "ds:KeyInfo";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyInfo {
    #[serde(rename = "Id")]
    pub id: Option<String>,
    #[serde(rename = "X509Data")]
    pub x509_data: Option<X509Data>,
}

impl KeyInfo {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(x509_data) = &self.x509_data {
            writer.write(x509_data.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const X509_DATA_NAME: &str = "ds:X509Data";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    pub certificates: Vec<String>,
}

impl X509Data {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
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
        Ok(String::from_utf8(write_buf)?)
    }
}
