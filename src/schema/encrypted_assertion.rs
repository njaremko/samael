use yaserde_derive::{YaDeserialize, YaSerialize};

use crate::{key_info::KeyInfo, signature::Transform};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct EncryptedAssertion {
    #[yaserde(rename = "EncryptedData", prefix = "xenc")]
    encrypted_data: EncryptedData,
    #[yaserde(rename = "EncryptedKey", prefix = "xenc", default)]
    encrypted_keys: Vec<EncryptedKey>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "xenc: http://www.w3.org/2001/04/xmlenc#"
)]
pub struct EncryptedData {
    #[yaserde(attribute, rename = "ID")]
    id: Option<String>,
    #[yaserde(attribute, rename = "Type")]
    r#type: Option<String>,
    #[yaserde(attribute, rename = "MimeType")]
    mime_type: Option<String>,
    #[yaserde(attribute, rename = "Encoding")]
    encoding: Option<String>,
    #[yaserde(rename = "EncryptionMethod", prefix = "xenc")]
    encryption_method: Option<EncryptionMethod>,
    #[yaserde(rename = "KeyInfo", prefix = "ds")]
    key_info: Option<KeyInfo>,
    #[yaserde(rename = "CipherData", prefix = "xenc")]
    cipher_data: CipherData,
    #[yaserde(rename = "EncryptionProperties", prefix = "xenc")]
    encryption_properties: Option<EncryptionProperties>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct EncryptionMethod {
    #[yaserde(attribute, rename = "Algorithm")]
    algorithm: String,
    #[yaserde(rename = "KeySize", prefix = "xenc")]
    key_size: Option<u32>,
    #[yaserde(rename = "OAEPparams", prefix = "xenc")]
    oaep_params: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct EncryptionProperties {
    #[yaserde(attribute, rename = "Id")]
    id: Option<String>,
    #[yaserde(rename = "EncryptionProperty", prefix = "xenc")]
    encryption_properties: Vec<EncryptionProperty>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct EncryptionProperty {
    #[yaserde(attribute, rename = "Target")]
    target: Option<String>,
    #[yaserde(attribute, rename = "Id")]
    id: Option<String>,
    #[yaserde(text)]
    value: String,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "xenc: http://www.w3.org/2001/04/xmlenc#"
)]
pub struct EncryptedKey {
    #[yaserde(attribute, rename = "ID")]
    id: Option<String>,
    #[yaserde(attribute, rename = "Type")]
    r#type: Option<String>,
    #[yaserde(attribute, rename = "MimeType")]
    mime_type: Option<String>,
    #[yaserde(attribute, rename = "Encoding")]
    encoding: Option<String>,
    #[yaserde(attribute, rename = "Recipient")]
    recipient: Option<String>,
    #[yaserde(rename = "EncryptionMethod", prefix = "xenc")]
    encryption_method: Option<EncryptionMethod>,
    #[yaserde(rename = "KeyInfo", prefix = "ds")]
    key_info: Option<KeyInfo>,
    #[yaserde(rename = "CipherData", prefix = "xenc")]
    cipher_data: CipherData,
    #[yaserde(rename = "EncryptionProperties", prefix = "xenc")]
    encryption_properties: Option<EncryptionProperties>,
    #[yaserde(rename = "ReferenceList", prefix = "xenc")]
    reference_list: Option<ReferenceList>,
    #[yaserde(rename = "CarriedKeyName", prefix = "xenc")]
    carried_key_name: Option<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct CipherData {
    #[yaserde(rename = "CipherValue", prefix = "xenc")]
    cipher_value: Option<String>,
    #[yaserde(rename = "CipherReference", prefix = "xenc")]
    cipher_reference: Option<CipherReference>,
}
#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct CipherReference {
    #[yaserde(rename = "Transforms", prefix = "xenc")]
    transforms: Option<Transforms>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct Transforms {
    #[yaserde(rename = "Transform", prefix = "ds")]
    transforms: Vec<Transform>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xenc: http://www.w3.org/2001/04/xmlenc#")]
pub struct ReferenceList {
    #[yaserde(rename = "DataReference", prefix = "xenc", default)]
    data_reference: Vec<DataOrKeyReference>,
    #[yaserde(rename = "KeyReference", prefix = "xenc", default)]
    key_reference: Vec<DataOrKeyReference>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct DataOrKeyReference {
    #[yaserde(attribute, rename = "URI")]
    uri: String,
}
