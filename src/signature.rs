use crate::key_info::{KeyInfo, X509Data};
use base64::{engine::general_purpose, Engine as _};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;
use std::str::FromStr;
use crate::crypto::CertificateDer;

const NAME: &str = "ds:Signature";
const SCHEMA: (&str, &str) = ("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Signature {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "KeyInfo")]
    pub key_info: Option<Vec<KeyInfo>>,
}

impl Signature {
    pub fn template(ref_id: &str, x509_cert_der: &CertificateDer) -> Self {
        Signature {
            id: None,
            signed_info: SignedInfo {
                id: None,
                canonicalization_method: CanonicalizationMethod {
                    algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                },
                signature_method: SignatureMethod {
                    algorithm: SignatureAlgorithm::RsaSha256,
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
                        algorithm: DigestAlgorithm::Sha1,
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

    pub fn add_key_info(&mut self, public_cert_der: &CertificateDer) -> &mut Self {
        self.key_info.get_or_insert(Vec::new()).push(KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![general_purpose::STANDARD.encode(public_cert_der.der_data())],
            }),
        });
        self
    }
}

impl TryFrom<Signature> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Signature> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        root.push_attribute(SCHEMA);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.signed_info).try_into()?;
        writer.write_event(event)?;
        let event: Event<'_> = (&value.signature_value).try_into()?;
        writer.write_event(event)?;
        if let Some(key_infos) = &value.key_info {
            for key_info in key_infos {
                let event: Event<'_> = key_info.try_into()?;
                writer.write_event(event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SIGNATURE_VALUE_NAME: &str = "ds:SignatureValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureValue {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "$value")]
    pub base64_content: Option<String>,
}

impl TryFrom<SignatureValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SignatureValue) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SignatureValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SignatureValue) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SIGNATURE_VALUE_NAME);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(ref base64_content) = value.base64_content {
            writer.write_event(Event::Text(BytesText::from_escaped(base64_content)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(SIGNATURE_VALUE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SIGNED_INFO_NAME: &str = "ds:SignedInfo";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignedInfo {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "Reference")]
    pub reference: Vec<Reference>,
}

impl TryFrom<SignedInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SignedInfo) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SignedInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SignedInfo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SIGNED_INFO_NAME);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.canonicalization_method).try_into()?;
        writer.write_event(event)?;
        let event: Event<'_> = (&value.signature_method).try_into()?;
        writer.write_event(event)?;
        for reference in &value.reference {
            let event: Event<'_> = reference.try_into()?;
            writer.write_event(event)?;
        }
        writer.write_event(Event::End(BytesEnd::new(SIGNED_INFO_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const CANONICALIZATION_METHOD: &str = "ds:CanonicalizationMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalizationMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

impl TryFrom<CanonicalizationMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: CanonicalizationMethod) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&CanonicalizationMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &CanonicalizationMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(CANONICALIZATION_METHOD);
        root.push_attribute(("Algorithm", value.algorithm.as_ref()));
        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SIGNATURE_METHOD_NAME: &str = "ds:SignatureMethod";
const HMAC_OUTPUT_LENGTH_NAME: &str = "ds:HMACOutputLength";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignatureMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: SignatureAlgorithm,
    #[serde(rename = "@ds:HMACOutputLength")]
    #[serde(alias = "@HMACOutputLength")]
    pub hmac_output_length: Option<usize>,
}

impl TryFrom<SignatureMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SignatureMethod) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SignatureMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SignatureMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        let mut root = BytesStart::new(SIGNATURE_METHOD_NAME);
        root.push_attribute(("Algorithm", value.algorithm.value()));

        if let Some(hmac_output_length) = &value.hmac_output_length {
            writer.write_event(Event::Start(root))?;

            writer.write_event(Event::Start(BytesStart::new(HMAC_OUTPUT_LENGTH_NAME)))?;

            writer.write_event(Event::Text(BytesText::from_escaped(
                hmac_output_length.to_string(),
            )))?;

            writer.write_event(Event::End(BytesEnd::new(HMAC_OUTPUT_LENGTH_NAME)))?;

            writer.write_event(Event::End(BytesEnd::new(SIGNATURE_METHOD_NAME)))?;
            writer.write_event(Event::End(BytesEnd::new(SIGNATURE_METHOD_NAME)))?;
        } else {
            writer.write_event(Event::Empty(root))?;
        }

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum SignatureAlgorithm {
    #[serde(rename = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")]
    RsaSha256,
    #[serde(rename = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")]
    Sha256RsaMGF1,
    #[serde(rename = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")]
    EcdsaSha256,
    #[serde(untagged)]
    Unsupported(String),
}

impl FromStr for SignatureAlgorithm {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => SignatureAlgorithm::RsaSha256,
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => {
                SignatureAlgorithm::Sha256RsaMGF1
            }
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => {
                SignatureAlgorithm::EcdsaSha256
            }
            i => SignatureAlgorithm::Unsupported(i.to_string()),
        })
    }
}

impl SignatureAlgorithm {
    const RSA_SHA256: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const SHA256_RSA_MGF1: &'static str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    const SHA256_ECDSA: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    pub fn value(&self) -> &str {
        match self {
            SignatureAlgorithm::RsaSha256 => Self::RSA_SHA256,
            SignatureAlgorithm::Sha256RsaMGF1 => Self::SHA256_RSA_MGF1,
            SignatureAlgorithm::EcdsaSha256 => Self::SHA256_ECDSA,
            SignatureAlgorithm::Unsupported(algo) => algo,
        }
    }
}

const TRANSFORMS_NAME: &str = "ds:Transforms";
const TRANSFORM_NAME: &str = "ds:Transform";
const XPATH_NAME: &str = "ds:XPath";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transform {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
    #[serde(rename = "@ds:XPath")]
    #[serde(alias = "@XPath")]
    pub xpath: Option<String>,
}

impl TryFrom<Transform> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Transform) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Transform> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Transform) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(TRANSFORM_NAME);
        root.push_attribute(("Algorithm", value.algorithm.as_ref()));

        if let Some(xpath) = &value.xpath {
            writer.write_event(Event::Start(root))?;

            let xpath_root = Event::Start(BytesStart::new(XPATH_NAME));
            writer.write_event(xpath_root)?;
            writer.write_event(Event::Text(BytesText::from_escaped(xpath)))?;
            writer.write_event(Event::End(BytesEnd::new(XPATH_NAME)))?;

            writer.write_event(Event::End(BytesEnd::new(TRANSFORM_NAME)))?;
        } else {
            writer.write_event(Event::Empty(root))?;
        }

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transforms {
    #[serde(rename = "Transform")]
    pub transforms: Vec<Transform>,
}

impl TryFrom<Transforms> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Transforms) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Transforms> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Transforms) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(TRANSFORMS_NAME);
        writer.write_event(Event::Start(root))?;
        for transform in &value.transforms {
            let event: Event<'_> = transform.try_into()?;
            writer.write_event(event)?;
        }
        writer.write_event(Event::End(BytesEnd::new(TRANSFORMS_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const DIGEST_METHOD: &str = "ds:DigestMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DigestMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: DigestAlgorithm,
}

impl TryFrom<DigestMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: DigestMethod) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&DigestMethod> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &DigestMethod) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(DIGEST_METHOD);
        root.push_attribute(("Algorithm", value.algorithm.value()));
        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum DigestAlgorithm {
    #[serde(rename = "http://www.w3.org/2000/09/xmldsig#sha1")]
    Sha1,
    #[serde(rename = "http://www.w3.org/2001/04/xmlenc#sha256")]
    Sha256,
    #[serde(untagged)]
    Unsupported(String),
}

impl DigestAlgorithm {
    const SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#sha1";
    const SHA256: &'static str = "http://www.w3.org/2001/04/xmlenc#sha256";

    pub fn value(&self) -> &str {
        match self {
            DigestAlgorithm::Sha1 => Self::SHA1,
            DigestAlgorithm::Sha256 => Self::SHA256,
            DigestAlgorithm::Unsupported(algo) => algo,
        }
    }
}

const DIGEST_VALUE_NAME: &str = "ds:DigestValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DigestValue {
    #[serde(rename = "$value")]
    pub base64_content: Option<String>,
}
impl TryFrom<DigestValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: DigestValue) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&DigestValue> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &DigestValue) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(DIGEST_VALUE_NAME);
        writer.write_event(Event::Start(root))?;
        if let Some(ref base64_content) = value.base64_content {
            writer.write_event(Event::Text(BytesText::from_escaped(base64_content)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(DIGEST_VALUE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
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

    #[serde(rename = "@URI")]
    pub uri: Option<String>,
    #[serde(rename = "@Type")]
    pub reference_type: Option<String>,
    #[serde(rename = "@Id")]
    pub id: Option<String>,
}

impl TryFrom<Reference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Reference) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Reference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Reference) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(REFERENCE_NAME);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        if let Some(uri) = &value.uri {
            root.push_attribute(("URI", uri.as_ref()));
        }
        if let Some(reference_type) = &value.reference_type {
            root.push_attribute(("Type", reference_type.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(transforms) = &value.transforms {
            let event: Event<'_> = transforms.try_into()?;
            writer.write_event(event)?;
        }

        let event: Event<'_> = (&value.digest_method).try_into()?;
        writer.write_event(event)?;
        if let Some(ref digest_value) = value.digest_value {
            let event: Event<'_> = digest_value.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(REFERENCE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use crate::traits::ToXml;

    use super::*;

    #[test]
    pub fn test_signature_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let signature = r##"
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#pfxe33e94d1-ae1f-a607-5c5d-f0fd9d1bd963"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>
</ds:Signature>
"##;
        let deserialized: Signature = quick_xml::de::from_str(signature)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: Signature = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }

    #[test]
    pub fn test_signedinfo_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let signed_info = r##"
<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#pfxe33e94d1-ae1f-a607-5c5d-f0fd9d1bd963"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>
"##;
        let deserialized: SignedInfo = quick_xml::de::from_str(signed_info)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: SignedInfo = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }

    #[test]
    pub fn test_canonicalizationmethod_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let canonicalization_method =
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#;
        let deserialized: CanonicalizationMethod =
            quick_xml::de::from_str(canonicalization_method)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: CanonicalizationMethod = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }

    #[test]
    pub fn test_signaturemethod_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let signature_method = r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#;
        let deserialized: SignatureMethod = quick_xml::de::from_str(signature_method)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: SignatureMethod = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        let algo = r#"<ds:SignatureMethod Algorithm="UNSUPPORTED" />"#;
        let deserialized: SignatureMethod = quick_xml::de::from_str(algo)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: SignatureMethod = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }

    #[test]
    pub fn test_transform_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;
        let deserialized: Transforms = quick_xml::de::from_str(transforms)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: Transforms = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }

    #[test]
    pub fn test_digestmethod_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let digest_method =
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />"#;
        let deserialized: DigestMethod = quick_xml::de::from_str(digest_method)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: DigestMethod = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        let digest_method = r#"<ds:DigestMethod Algorithm="UNSUPPORTED" />"#;
        let deserialized: DigestMethod = quick_xml::de::from_str(digest_method)?;
        let serialized = deserialized.to_string()?;
        let re_deserialized: DigestMethod = quick_xml::de::from_str(&serialized)?;
        assert_eq!(deserialized, re_deserialized);

        Ok(())
    }
}
