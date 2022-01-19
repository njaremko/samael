use crate::attribute::AttributeValue;
use crate::metadata::LocalizedName;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct AttributeConsumingService {
    #[yaserde(attribute)]
    pub index: u16,
    #[yaserde(attribute, rename = "isDefault")]
    pub is_default: Option<bool>,
    #[yaserde(rename = "ServiceName", prefix = "md")]
    pub service_names: Vec<LocalizedName>,
    #[yaserde(rename = "ServiceDescription", prefix = "md", default)]
    pub service_descriptions: Vec<LocalizedName>,
    #[yaserde(rename = "RequestedAttribute", prefix = "md")]
    pub request_attributes: Vec<RequestedAttribute>,
}

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
#[yaserde(namespace = "md: urn:oasis:names:tc:SAML:2.0:metadata")]
pub struct RequestedAttribute {
    #[yaserde(attribute, rename = "Name")]
    pub name: String,
    #[yaserde(attribute, rename = "NameFormat")]
    pub name_format: Option<String>,
    #[yaserde(attribute, rename = "FriendlyName")]
    pub friendly_name: Option<String>,
    #[yaserde(attribute, rename = "isRequired")]
    pub is_required: Option<bool>,
    #[yaserde(rename = "AttributeValue", default)]
    pub values: Vec<AttributeValue>,
}
