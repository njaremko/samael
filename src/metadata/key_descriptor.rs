use crate::key_info::KeyInfo;
use crate::metadata::EncryptionMethod;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata"
)]
pub struct KeyDescriptor {
    #[yaserde(attribute, rename = "use")]
    pub key_use: Option<String>,
    #[yaserde(rename = "KeyInfo", prefix = "ds")]
    pub key_info: KeyInfo,
    #[yaserde(rename = "EncryptionMethod", prefix = "md", default)]
    pub encryption_methods: Vec<EncryptionMethod>,
}

impl KeyDescriptor {
    pub fn is_signing(&self) -> bool {
        self.key_use
            .as_ref()
            .map(|u| u == "signing")
            .unwrap_or(false)
    }
}
