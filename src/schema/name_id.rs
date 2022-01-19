use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    Clone, Debug, YaDeserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct NameId {
    #[yaserde(attribute, rename = "NameQualifier")]
    pub name_qualifier: Option<String>,
    #[yaserde(attribute, rename = "SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[yaserde(attribute, rename = "Format")]
    pub format: Option<String>,
    #[yaserde(attribute, rename = "SPProvidedID")]
    pub sp_provided_id: Option<String>,
    #[yaserde(text)]
    pub value: String,
}
