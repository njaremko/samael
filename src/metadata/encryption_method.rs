use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct EncryptionMethod {
    #[yaserde(attribute, rename = "Algorithm")]
    pub algorithm: String,
}
