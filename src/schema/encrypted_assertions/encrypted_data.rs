use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedData {
    #[serde(rename = "EncryptionMethod")]
    pub method: EncryptionMethod,
    #[serde(rename = "CipherData")]
    pub encryption_cipher_data: Option<EncryptedCipherData>,
    #[serde(rename = "KeyInfo")]
    pub signature_key_info: Option<Vec<EncryptionKeyInfo>>,
}

impl EncryptedData {
    fn name() -> &'static str {
        "xenc:EncryptedData"
    }
}

impl TryFrom<&EncryptedData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(EncryptedData::name());

        // Attaching namespace attributes
        root.push_attribute(("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"));
        root.push_attribute(("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"));
        root.push_attribute(("Type", "http://www.w3.org/2001/04/xmlenc#Element"));

        writer.write_event(Event::Start(root))?;
        let encryption_event: Event<'_> = (&value.method).try_into()?;
        writer.write_event(encryption_event)?;
        if let Some(cipher_data) = value.encryption_cipher_data.as_ref() {
            let event_data: Event<'_> = cipher_data.try_into()?;
            writer.write_event(event_data)?;
        }

        // Writing any signatures.
        if let Some(signature_key_info) = value.signature_key_info.as_ref() {
            for sig in signature_key_info {
                let sig_event: Event<'_> = sig.try_into()?;
                writer.write_event(sig_event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(EncryptedData::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
