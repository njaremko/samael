use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

pub enum SubjectType<'a> {
    BaseId,
    NameId(&'a str),
    EncryptedId,
}

impl<'a> SubjectType<'a> {
    fn saml_element_name(&self) -> &'static str {
        match self {
            SubjectType::BaseId => "saml2:BaseID",
            SubjectType::NameId(_) => "saml2:NameID",
            SubjectType::EncryptedId => "saml2:EncryptedID",
        }
    }
}

impl<'a> TryFrom<SubjectType<'a>> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectType) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<'a> TryFrom<&SubjectType<'a>> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectType) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let elem_name = value.saml_element_name();
        let root = BytesStart::new(elem_name);
        writer.write_event(Event::Start(root))?;
        if let SubjectType::NameId(content) = value {
            writer.write_event(Event::Text(BytesText::from_escaped(*content)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(elem_name)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const NAME: &str = "saml2:Subject";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Subject {
    #[serde(rename = "NameID")]
    pub name_id: Option<SubjectNameID>,
    #[serde(rename = "SubjectConfirmation")]
    pub subject_confirmations: Option<Vec<SubjectConfirmation>>,
}

impl TryFrom<Subject> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Subject) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Subject> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Subject) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        root.push_attribute(SCHEMA);

        writer.write_event(Event::Start(root))?;
        if let Some(name_id) = &value.name_id {
            let event: Event<'_> = name_id.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(subject_confirmations) = &value.subject_confirmations {
            for confirmation in subject_confirmations {
                let event: Event<'_> = confirmation.try_into()?;
                writer.write_event(event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectNameID {
    #[serde(rename = "@Format")]
    pub format: Option<String>,

    #[serde(rename = "$value")]
    pub value: String,
}

impl SubjectNameID {
    fn name() -> &'static str {
        "saml2:NameID"
    }
}

impl TryFrom<SubjectNameID> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectNameID) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SubjectNameID> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectNameID) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SubjectNameID::name());

        if let Some(format) = &value.format {
            root.push_attribute(("Format", format.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(SubjectNameID::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SUBJECT_CONFIRMATION_NAME: &str = "saml2:SubjectConfirmation";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectConfirmation {
    #[serde(rename = "@Method")]
    pub method: Option<String>,
    #[serde(rename = "NameID")]
    pub name_id: Option<SubjectNameID>,
    #[serde(rename = "SubjectConfirmationData")]
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

impl TryFrom<SubjectConfirmation> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectConfirmation) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SubjectConfirmation> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectConfirmation) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SUBJECT_CONFIRMATION_NAME);
        if let Some(method) = &value.method {
            root.push_attribute(("Method", method.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(name_id) = &value.name_id {
            let event: Event<'_> = name_id.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(subject_confirmation_data) = &value.subject_confirmation_data {
            let event: Event<'_> = subject_confirmation_data.try_into()?;
            writer.write_event(event)?;
        }
        writer.write_event(Event::End(BytesEnd::new(SUBJECT_CONFIRMATION_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SUBJECT_CONFIRMATION_DATA_NAME: &str = "saml2:SubjectConfirmationData";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectConfirmationData {
    #[serde(rename = "@NotBefore")]
    pub not_before: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@NotOnOrAfter")]
    pub not_on_or_after: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@Recipient")]
    pub recipient: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "@Address")]
    pub address: Option<String>,
    #[serde(rename = "$value")]
    pub content: Option<String>,
}

impl TryFrom<SubjectConfirmationData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectConfirmationData) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SubjectConfirmationData> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectConfirmationData) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SUBJECT_CONFIRMATION_DATA_NAME);
        if let Some(not_before) = &value.not_before {
            root.push_attribute((
                "NotBefore",
                not_before
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(not_on_or_after) = &value.not_on_or_after {
            root.push_attribute((
                "NotOnOrAfter",
                not_on_or_after
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(recipient) = &value.recipient {
            root.push_attribute(("Recipient", recipient.as_ref()));
        }
        if let Some(in_response_to) = &value.in_response_to {
            root.push_attribute(("InResponseTo", in_response_to.as_ref()));
        }
        if let Some(address) = &value.address {
            root.push_attribute(("Address", address.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(content) = &value.content {
            writer.write_event(Event::Text(BytesText::from_escaped(content)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(SUBJECT_CONFIRMATION_DATA_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
