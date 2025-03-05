use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[cfg(feature = "xmlsec")]
use crate::crypto::{decrypt, decrypt_aead};
#[cfg(feature = "xmlsec")]
use crate::schema::Assertion;
#[cfg(feature = "xmlsec")]
use crate::service_provider::Error;
#[cfg(feature = "xmlsec")]
use openssl::pkey::{PKey, Private};

use crate::key_info::{EncryptedKeyInfo, KeyInfo};
use crate::signature::DigestMethod;

const NAME: &str = "saml2:EncryptedAssertion";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedAssertion {
    #[serde(rename = "EncryptedData")]
    pub data: Option<EncryptedData>,
    #[serde(rename = "EncryptedKey")]
    pub encrypted_key: Option<EncryptedKey>,
}

impl EncryptedAssertion {
    pub fn encrypted_key_info(&self) -> Option<(&CipherValue, &String)> {
        self.data.as_ref().and_then(|ed| ed.key_info()).or_else(|| {
            self.encrypted_key
                .as_ref()
                .and_then(|e| e.cipher_data.as_ref().zip(e.encryption_method.as_ref()))
                .and_then(|(cd, em)| cd.cipher_value.as_ref().zip(em.algorithm.as_ref()))
        })
    }

    pub fn encrypted_value_info(&self) -> Option<(&CipherValue, &String)> {
        self.data.as_ref().and_then(|ed| ed.value_info())
    }

    #[cfg(feature = "xmlsec")]
    pub fn decrypt(&self, decryption_key: &PKey<Private>) -> Result<Assertion, Error> {
        let (ekey, method) = self
            .encrypted_key_info()
            .ok_or(Error::MissingEncryptedKeyInfo)?;
        let decrypted_key = decrypt_assertion_key_info(ekey, method, decryption_key)?;

        let (evalue, method) = self
            .encrypted_value_info()
            .ok_or(Error::MissingEncryptedValueInfo)?;
        decrypt_assertion_value_info(evalue, method, &decrypted_key)
    }
}

impl TryFrom<EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptedAssertion) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedAssertion) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(NAME, NAME.len());
        root.push_attribute(SCHEMA);

        writer.write_event(Event::Start(root))?;

        if let Some(encrypted_data) = &value.data {
            let event: Event<'_> = encrypted_data.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(feature = "xmlsec")]
fn decrypt_assertion_key_info(
    cipher_value: &CipherValue,
    method: &str,
    decryption_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<Vec<u8>, Error> {
    use openssl::rsa::Padding;

    let padding = match method {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Padding::PKCS1_OAEP,
        "http://www.w3.org/2001/04/xmlenc#rsa-1_5" => Padding::PKCS1,
        _ => {
            return Err(Error::EncryptedAssertionKeyMethodUnsupported {
                method: method.to_string(),
            });
        }
    };

    let encrypted_key =
        openssl::base64::decode_block(&cipher_value.value.lines().collect::<String>())?;
    let pkey_size = decryption_key.size() as usize;
    let mut decrypted_key = vec![0u8; pkey_size];
    let rsa = decryption_key.rsa()?;
    let i = rsa.private_decrypt(&encrypted_key, &mut decrypted_key, padding)?;
    Ok(decrypted_key[0..i].to_vec())
}

#[cfg(feature = "xmlsec")]
fn decrypt_assertion_value_info(
    cipher_value: &CipherValue,
    method: &str,
    decryption_key: &[u8],
) -> Result<Assertion, Error> {
    use openssl::symm::Cipher;

    let encoded_value =
        openssl::base64::decode_block(&cipher_value.value.lines().collect::<String>())?;

    let plaintext = match method {
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => {
            let cipher = Cipher::aes_128_cbc();
            let iv_len = cipher.iv_len().unwrap();
            decrypt(
                cipher,
                decryption_key,
                Some(&encoded_value[0..iv_len]),
                &encoded_value[iv_len..],
            )?
        }
        "http://www.w3.org/2009/xmlenc11#aes128-gcm" => {
            let cipher = Cipher::aes_128_gcm();
            let iv_len = cipher.iv_len().unwrap();
            let tag_len = 16 as usize;
            let data_end = encoded_value.len() - tag_len;
            decrypt_aead(
                cipher,
                decryption_key,
                Some(&encoded_value[0..iv_len]),
                &[],
                &encoded_value[iv_len..data_end],
                &encoded_value[data_end..],
            )?
        }
        _ => {
            return Err(Error::EncryptedAssertionValueMethodUnsupported {
                method: method.to_string(),
            });
        }
    };

    let assertion_string = match String::from_utf8(plaintext) {
        Ok(s) => s,
        Err(e) => {
            let i = e.utf8_error().valid_up_to();
            let mut plaintext = e.into_bytes();
            plaintext.truncate(i);
            let s = String::from_utf8(plaintext).map_err(|_| Error::EncryptedAssertionInvalid)?;
            let fi = s.find("<").unwrap();
            let li = s.rfind(">").unwrap();
            s[fi..li + 1].to_owned()
        }
    };

    quick_xml::de::from_str(&assertion_string).map_err(|_e| Error::FailedToDecryptAssertion)
}

const ED_NAME: &str = "xenc:EncryptedData";
const ED_SCHEMA: (&str, &str) = ("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedData {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "@Type")]
    pub ty: Option<String>,
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: Option<EncryptionMethod>,
    #[serde(alias = "KeyInfo", alias = "ds:KeyInfo")]
    pub key_info: Option<EncryptedKeyInfo>,
    #[serde(rename = "CipherData")]
    pub cipher_data: Option<CipherData>,
}

impl EncryptedData {
    pub fn key_info(&self) -> Option<(&CipherValue, &String)> {
        self.key_info
            .as_ref()
            .and_then(|k| k.encrypted_key.as_ref())
            .and_then(|e| e.cipher_data.as_ref().zip(e.encryption_method.as_ref()))
            .and_then(|(cd, em)| cd.cipher_value.as_ref().zip(em.algorithm.as_ref()))
    }

    pub fn value_info(&self) -> Option<(&CipherValue, &String)> {
        self.cipher_data
            .as_ref()
            .zip(self.encryption_method.as_ref())
            .and_then(|(cd, em)| cd.cipher_value.as_ref().zip(em.algorithm.as_ref()))
    }
}

impl TryFrom<EncryptedData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptedData) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptedData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(ED_NAME, ED_NAME.len());
        root.push_attribute(ED_SCHEMA);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        if let Some(ty) = &value.ty {
            root.push_attribute(("Type", ty.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(encryption_method) = &value.encryption_method {
            let event: Event<'_> = encryption_method.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(key_info) = &value.key_info {
            let event: Event<'_> = key_info.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(cipher_data) = &value.cipher_data {
            let event: Event<'_> = cipher_data.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(ED_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const EM_NAME: &str = "xenc:EncryptionMethod";
const EM_SCHEMA: (&str, &str) = ("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: Option<String>,
    #[serde(rename = "DigestMethod")]
    pub digest_method: Option<DigestMethod>,
}

impl TryFrom<EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptionMethod) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptionMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptionMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(EM_NAME, EM_NAME.len());
        root.push_attribute(EM_SCHEMA);
        if let Some(algorithm) = &value.algorithm {
            root.push_attribute(("Algorithm", algorithm.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(digest_method) = &value.digest_method {
            let event: Event<'_> = digest_method.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(EM_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const CD_NAME: &str = "xenc:CipherData";
const CD_SCHEMA: (&str, &str) = ("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CipherData {
    #[serde(rename = "CipherValue")]
    pub cipher_value: Option<CipherValue>,
}

impl TryFrom<CipherData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: CipherData) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&CipherData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &CipherData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(CD_NAME, CD_NAME.len());
        root.push_attribute(CD_SCHEMA);

        writer.write_event(Event::Start(root))?;

        if let Some(cipher_value) = &value.cipher_value {
            let event: Event<'_> = cipher_value.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(CD_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const CV_NAME: &str = "xenc:CipherValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CipherValue {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<CipherValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: CipherValue) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&CipherValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &CipherValue) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::from_content(CV_NAME, CV_NAME.len());

        writer.write_event(Event::Start(root))?;

        writer.write_event(Event::Text(BytesText::new(&value.value)))?;

        writer.write_event(Event::End(BytesEnd::new(CV_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const EK_NAME: &str = "xenc:EncryptedKey";
const EK_SCHEMA: (&str, &str) = ("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedKey {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "@Recipient")]
    pub recipient: Option<String>,
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: Option<EncryptionMethod>,
    #[serde(rename = "KeyInfo")]
    pub key_info: Option<KeyInfo>,
    #[serde(rename = "CipherData")]
    pub cipher_data: Option<CipherData>,
}

impl TryFrom<EncryptedKey> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: EncryptedKey) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EncryptedKey> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedKey) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(EK_NAME, EK_NAME.len());
        root.push_attribute(EK_SCHEMA);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        if let Some(recipient) = &value.recipient {
            root.push_attribute(("Recipient", recipient.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(encryption_method) = &value.encryption_method {
            let event: Event<'_> = encryption_method.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(key_info) = &value.key_info {
            let event: Event<'_> = key_info.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(cipher_data) = &value.cipher_data {
            let event: Event<'_> = cipher_data.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(EK_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use crate::schema::Response;

    #[test]
    fn test_encrypted_assertion_key_info() {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_encrypted.xml",
        ));
        let response: Response = response_xml
            .parse()
            .expect("failed to parse response_encrypted.xml");

        let encrypted_assertion = response
            .encrypted_assertion
            .expect("EncryptedAssertion missing");
        let key_info = encrypted_assertion.encrypted_key_info();

        let key_info_exists = key_info.is_some();

        assert!(key_info_exists, "KeyInfo missing on EncryptedAssertion");
    }
}
