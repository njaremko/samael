use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "xsi: http://www.w3.org/2001/XMLSchema-instance")]
pub struct AttributeValue {
    #[yaserde(attribute, rename = "type", prefix = "xsi")]
    pub attribute_type: Option<String>,
    #[yaserde(text)]
    pub value: Option<String>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct Attribute {
    #[yaserde(attribute, rename = "FriendlyName")]
    pub friendly_name: Option<String>,
    #[yaserde(attribute, rename = "Name")]
    pub name: Option<String>,
    #[yaserde(attribute, rename = "NameFormat")]
    pub name_format: Option<String>,
    #[yaserde(rename = "AttributeValue", prefix = "saml", default)]
    pub values: Vec<AttributeValue>,
}
