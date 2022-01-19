use yaserde_derive::{YaDeserialize, YaSerialize};

#[derive(
    YaDeserialize, YaSerialize, Debug, Default, Clone, Hash, Eq, PartialEq, Ord, PartialOrd,
)]
pub struct NameIdPolicy {
    #[yaserde(attribute, rename = "Format")]
    pub format: Option<String>,
    #[yaserde(attribute, rename = "SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[yaserde(attribute, rename = "AllowCreate")]
    pub allow_create: Option<bool>,
}
