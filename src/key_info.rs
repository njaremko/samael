use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct KeyInfo {
    #[yaserde(attribute, rename = "Id")]
    pub id: Option<String>,
    #[yaserde(rename = "X509Data", prefix = "ds")]
    pub x509_data: Option<X509Data>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "ds: http://www.w3.org/2000/09/xmldsig#")]
pub struct X509Data {
    #[yaserde(rename = "X509Certificate", prefix = "ds")]
    pub certificates: Vec<String>,
}
