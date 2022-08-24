use crate::key_info::{KeyInfo, X509Data};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "ds:Signature";
const SCHEMA: (&str, &str) = ("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Signature {
    #[serde(rename = "Id")]
    pub id: Option<String>,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "KeyInfo")]
    pub key_info: Option<Vec<KeyInfo>>,
}

impl Signature {
    pub fn template(ref_id: &str, x509_cert_der: &[u8]) -> Self {
        Signature {
            id: None,
            signed_info: SignedInfo {
                id: None,
                canonicalization_method: CanonicalizationMethod {
                    algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                },
                signature_method: SignatureMethod {
                    algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string(),
                    hmac_output_length: None,
                },
                reference: vec![Reference {
                    transforms: Some(Transforms {
                        transforms: vec![
                            Transform {
                                algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                                    .to_string(),
                                xpath: None,
                            },
                            Transform {
                                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                                xpath: None,
                            },
                        ],
                    }),
                    digest_method: DigestMethod {
                        algorithm: "http://www.w3.org/2000/09/xmldsig#sha1".to_string(),
                    },
                    digest_value: Some(DigestValue {
                        base64_content: Some("".to_string()),
                    }),
                    uri: Some(format!("#{}", ref_id)),
                    reference_type: None,
                    id: None,
                }],
            },
            signature_value: SignatureValue {
                id: None,
                base64_content: Some("".to_string()),
            },
            key_info: Some(vec![KeyInfo {
                id: None,
                x509_data: Some(X509Data {
                    certificates: vec![crate::crypto::mime_encode_x509_cert(x509_cert_der)],
                }),
            }]),
        }
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write(self.signed_info.to_xml()?.as_bytes())?;
        writer.write(self.signature_value.to_xml()?.as_bytes())?;
        if let Some(key_infos) = &self.key_info {
            for key_info in key_infos {
                writer.write(key_info.to_xml()?.as_bytes())?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }

    pub fn add_key_info(&mut self, public_cert_der: &[u8]) -> &mut Self {
        self.key_info.get_or_insert(Vec::new()).push(KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![base64::encode(public_cert_der)],
            }),
        });
        self
    }
}

const SIGNATURE_VALUE_NAME: &str = "ds:SignatureValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureValue {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "$value")]
    pub base64_content: Option<String>,
}

impl SignatureValue {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root =
            BytesStart::borrowed(SIGNATURE_VALUE_NAME.as_bytes(), SIGNATURE_VALUE_NAME.len());
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(ref base64_content) = self.base64_content {
            writer.write_event(Event::Text(BytesText::from_plain_str(base64_content)))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(
            SIGNATURE_VALUE_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const SIGNED_INFO_NAME: &str = "ds:SignedInfo";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignedInfo {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "Reference")]
    pub reference: Vec<Reference>,
}

impl SignedInfo {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(SIGNED_INFO_NAME.as_bytes(), SIGNED_INFO_NAME.len());
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write(self.canonicalization_method.to_xml()?.as_bytes())?;
        writer.write(self.signature_method.to_xml()?.as_bytes())?;
        for reference in &self.reference {
            writer.write(reference.to_xml()?.as_bytes())?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(SIGNED_INFO_NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const CANONICALIZATION_METHOD: &str = "ds:CanonicalizationMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalizationMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

impl CanonicalizationMethod {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(
            CANONICALIZATION_METHOD.as_bytes(),
            CANONICALIZATION_METHOD.len(),
        );
        root.push_attribute(("Algorithm", self.algorithm.as_ref()));
        writer.write_event(Event::Empty(root))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const SIGNATURE_METHOD_NAME: &str = "ds:SignatureMethod";
const HMAC_OUTPUT_LENGTH_NAME: &str = "ds:HMACOutputLength";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
    #[serde(rename = "ds:HMACOutputLength")]
    pub hmac_output_length: Option<usize>,
}

impl SignatureMethod {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let mut root = BytesStart::borrowed(
            SIGNATURE_METHOD_NAME.as_bytes(),
            SIGNATURE_METHOD_NAME.len(),
        );
        root.push_attribute(("Algorithm", self.algorithm.as_ref()));

        if let Some(hmac_output_length) = &self.hmac_output_length {
            writer.write_event(Event::Start(root))?;

            writer.write_event(Event::Start(BytesStart::borrowed(
                HMAC_OUTPUT_LENGTH_NAME.as_bytes(),
                HMAC_OUTPUT_LENGTH_NAME.len(),
            )))?;

            writer.write_event(Event::Text(BytesText::from_plain_str(
                hmac_output_length.to_string().as_ref(),
            )))?;

            writer.write_event(Event::End(BytesEnd::borrowed(
                HMAC_OUTPUT_LENGTH_NAME.as_bytes(),
            )))?;

            writer.write_event(Event::End(BytesEnd::borrowed(
                SIGNATURE_METHOD_NAME.as_bytes(),
            )))?;
        } else {
            writer.write_event(Event::Empty(root))?;
        }

        Ok(String::from_utf8(write_buf)?)
    }
}

const TRANSFORMS_NAME: &str = "ds:Transforms";
const TRANSFORM_NAME: &str = "ds:Transform";
const XPATH_NAME: &str = "ds:XPath";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transform {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
    #[serde(rename = "ds:XPath")]
    pub xpath: Option<String>,
}

impl Transform {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(TRANSFORM_NAME.as_bytes(), TRANSFORM_NAME.len());
        root.push_attribute(("Algorithm", self.algorithm.as_ref()));

        if let Some(xpath) = &self.xpath {
            writer.write_event(Event::Start(root))?;

            let xpath_root = Event::Start(BytesStart::borrowed(
                XPATH_NAME.as_bytes(),
                XPATH_NAME.len(),
            ));
            writer.write_event(xpath_root)?;
            writer.write_event(Event::Text(BytesText::from_plain_str(xpath.as_ref())))?;
            writer.write_event(Event::End(BytesEnd::borrowed(XPATH_NAME.as_bytes())))?;

            writer.write_event(Event::End(BytesEnd::borrowed(TRANSFORM_NAME.as_bytes())))?;
        } else {
            writer.write_event(Event::Empty(root))?;
        }

        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transforms {
    #[serde(rename = "Transform")]
    pub transforms: Vec<Transform>,
}

impl Transforms {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::borrowed(TRANSFORMS_NAME.as_bytes(), TRANSFORMS_NAME.len());
        writer.write_event(Event::Start(root))?;
        for transform in &self.transforms {
            writer.write(transform.to_xml()?.as_bytes())?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(TRANSFORMS_NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const DIGEST_METHOD: &str = "ds:DigestMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DigestMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

impl DigestMethod {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(DIGEST_METHOD.as_bytes(), DIGEST_METHOD.len());
        root.push_attribute(("Algorithm", self.algorithm.as_ref()));
        writer.write_event(Event::Empty(root))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const DIGEST_VALUE_NAME: &str = "ds:DigestValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DigestValue {
    #[serde(rename = "$value")]
    pub base64_content: Option<String>,
}

impl DigestValue {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::borrowed(DIGEST_VALUE_NAME.as_bytes(), DIGEST_VALUE_NAME.len());
        writer.write_event(Event::Start(root))?;
        if let Some(ref base64_content) = self.base64_content {
            writer.write_event(Event::Text(BytesText::from_plain_str(base64_content)))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(DIGEST_VALUE_NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const REFERENCE_NAME: &str = "ds:Reference";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Reference {
    #[serde(rename = "Transforms")]
    pub transforms: Option<Transforms>,
    #[serde(rename = "DigestMethod")]
    pub digest_method: DigestMethod,
    #[serde(rename = "DigestValue")]
    pub digest_value: Option<DigestValue>,

    #[serde(rename = "URI")]
    pub uri: Option<String>,
    #[serde(rename = "Type")]
    pub reference_type: Option<String>,
    #[serde(rename = "Id")]
    pub id: Option<String>,
}

impl Reference {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(REFERENCE_NAME.as_bytes(), REFERENCE_NAME.len());
        if let Some(id) = &self.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        if let Some(uri) = &self.uri {
            root.push_attribute(("URI", uri.as_ref()));
        }
        if let Some(reference_type) = &self.reference_type {
            root.push_attribute(("Type", reference_type.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(transforms) = &self.transforms {
            writer.write(transforms.to_xml()?.as_bytes())?;
        }

        writer.write(self.digest_method.to_xml()?.as_bytes())?;
        if let Some(ref digest_value) = self.digest_value {
            writer.write(digest_value.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(REFERENCE_NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
