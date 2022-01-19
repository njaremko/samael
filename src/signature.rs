use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::key_info::{KeyInfo, X509Data};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct Signature {
    #[yaserde(attribute)]
    pub id: Option<String>,
    #[yaserde(rename = "signedInfo", prefix = "ds")]
    pub signed_info: SignedInfo,
    #[yaserde(rename = "signatureValue", prefix = "ds")]
    pub signature_value: SignatureValue,
    #[yaserde(rename = "keyInfo", prefix = "ds", default)]
    pub key_info: Vec<KeyInfo>,
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
                    digest_value: DigestValue {
                        base64_content: Some("".to_string()),
                    },
                    uri: Some(format!("#{}", ref_id)),
                    reference_type: None,
                    id: None,
                }],
            },
            signature_value: SignatureValue {
                id: None,
                base64_content: Some("".to_string()),
            },
            key_info: vec![KeyInfo {
                id: None,
                x509_data: Some(X509Data {
                    certificates: vec![crate::crypto::mime_encode_x509_cert(x509_cert_der)],
                }),
            }],
        }
    }

    pub fn add_key_info(&mut self, public_cert_der: &[u8]) -> &mut Self {
        self.key_info.push(KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![base64::encode(public_cert_der)],
            }),
        });
        self
    }
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct SignatureValue {
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(text)]
    pub base64_content: Option<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct SignedInfo {
    #[yaserde(attribute, rename = "ID")]
    pub id: Option<String>,
    #[yaserde(rename = "CanonicalizationMethod", prefix = "ds")]
    pub canonicalization_method: CanonicalizationMethod,
    #[yaserde(rename = "SignatureMethod", prefix = "ds")]
    pub signature_method: SignatureMethod,
    #[yaserde(rename = "Reference", prefix = "ds")]
    pub reference: Vec<Reference>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct CanonicalizationMethod {
    #[yaserde(attribute, rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct SignatureMethod {
    #[yaserde(attribute, rename = "Algorithm")]
    pub algorithm: String,
    #[yaserde(rename = "HMACOutputLength", prefix = "ds")]
    pub hmac_output_length: Option<u32>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct Transform {
    #[yaserde(attribute, rename = "Algorithm")]
    pub algorithm: String,
    #[yaserde(rename = "XPath", prefix = "ds")]
    pub xpath: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct Transforms {
    #[yaserde(rename = "Transform", prefix = "ds")]
    pub transforms: Vec<Transform>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct DigestMethod {
    #[yaserde(attribute, rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct DigestValue {
    #[yaserde(text)]
    pub base64_content: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct Reference {
    #[yaserde(attribute, rename = "Id")]
    pub id: Option<String>,
    #[yaserde(attribute, rename = "URI")]
    pub uri: Option<String>,
    #[yaserde(attribute, rename = "Type")]
    pub reference_type: Option<String>,
    #[yaserde(rename = "Transforms", prefix = "ds")]
    pub transforms: Option<Transforms>,
    #[yaserde(rename = "DigestMethod", prefix = "ds")]
    pub digest_method: DigestMethod,
    #[yaserde(rename = "DigestValue", prefix = "ds")]
    pub digest_value: DigestValue,
}
