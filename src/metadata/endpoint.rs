use yaserde_derive::{YaDeserialize, YaSerialize};

// TODO: check where this is used

#[derive(Clone, Debug, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize)]
pub struct Endpoint {
    #[yaserde(attribute, rename = "Binding")]
    pub binding: String,
    #[yaserde(attribute, rename = "Location")]
    pub location: String,
    #[yaserde(attribute, rename = "ResponseLocation")]
    pub response_location: Option<String>,
}

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct IndexedEndpoint {
    #[yaserde(attribute, rename = "Binding")]
    pub binding: String,
    #[yaserde(attribute, rename = "Location")]
    pub location: String,
    #[yaserde(attribute, rename = "ResponseLocation")]
    pub response_location: Option<String>,
    #[yaserde(attribute)]
    pub index: u16,
    #[yaserde(attribute, rename = "isDefault")]
    pub is_default: Option<bool>,
}
