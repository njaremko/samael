use std::io::Write;

use quick_xml::Writer;

pub mod attribute;
#[cfg(feature = "xmlsec")]
mod bindings;
pub mod crypto;
#[cfg(feature = "xmlsec")]
pub mod idp;
pub mod key_info;
pub mod metadata;
pub mod schema;
pub mod service_provider;
pub mod signature;
#[cfg(feature = "xmlsec")]
mod xmlsec;

#[macro_use]
extern crate derive_builder;

#[cfg(feature = "xmlsec")]
pub fn init() -> xmlsec::XmlSecResult<xmlsec::XmlSecContext> {
    xmlsec::XmlSecContext::new()
}

pub trait ToXml {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>>;

    fn as_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        self.to_xml(&mut writer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

impl<T: ToXml> ToXml for Option<T> {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(t) = self {
            t.to_xml(writer)?;
        }
        Ok(())
    }
}

impl<T: ToXml> ToXml for Vec<T> {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        for t in self {
            t.to_xml(writer)?;
        }
        Ok(())
    }
}
