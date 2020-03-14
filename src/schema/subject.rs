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

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let elem_name = self.saml_element_name();
        let root = BytesStart::borrowed(elem_name.as_bytes(), elem_name.len());
        writer.write_event(Event::Start(root))?;
        if let SubjectType::NameId(content) = self {
            writer.write_event(Event::Text(BytesText::from_plain_str(content)))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(elem_name.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
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

impl Subject {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);

        writer.write_event(Event::Start(root))?;
        if let Some(name_id) = &self.name_id {
            writer.write(name_id.to_xml()?.as_bytes())?;
        }
        if let Some(subject_confirmations) = &self.subject_confirmations {
            for confirmation in subject_confirmations {
                writer.write(confirmation.to_xml()?.as_bytes())?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectNameID {
    #[serde(rename = "Format")]
    pub format: Option<String>,

    #[serde(rename = "$value")]
    pub value: String,
}

impl SubjectNameID {
    fn name() -> &'static str {
        "saml2:NameID"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        if let Some(format) = &self.format {
            root.push_attribute(("Format", format.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        writer.write(self.value.as_bytes())?;
        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const SUBJECT_CONFIRMATION_NAME: &str = "saml2:SubjectConfirmation";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectConfirmation {
    #[serde(rename = "Method")]
    pub method: Option<String>,
    #[serde(rename = "NameID")]
    pub name_id: Option<SubjectNameID>,
    #[serde(rename = "SubjectConfirmationData")]
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

impl SubjectConfirmation {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(
            SUBJECT_CONFIRMATION_NAME.as_bytes(),
            SUBJECT_CONFIRMATION_NAME.len(),
        );
        if let Some(method) = &self.method {
            root.push_attribute(("Method", method.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(name_id) = &self.name_id {
            writer.write(name_id.to_xml()?.as_bytes())?;
        }
        if let Some(subject_confirmation_data) = &self.subject_confirmation_data {
            writer.write(subject_confirmation_data.to_xml()?.as_bytes())?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(
            SUBJECT_CONFIRMATION_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
const SUBJECT_CONFIRMATION_DATA_NAME: &str = "saml2:SubjectConfirmationData";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectConfirmationData {
    #[serde(rename = "NotBefore")]
    pub not_before: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "Recipient")]
    pub recipient: Option<String>,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "Address")]
    pub address: Option<String>,
    #[serde(rename = "$value")]
    pub content: Option<String>,
}

impl SubjectConfirmationData {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(
            SUBJECT_CONFIRMATION_DATA_NAME.as_bytes(),
            SUBJECT_CONFIRMATION_DATA_NAME.len(),
        );
        if let Some(not_before) = &self.not_before {
            root.push_attribute((
                "NotBefore",
                not_before
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(not_on_or_after) = &self.not_on_or_after {
            root.push_attribute((
                "NotOnOrAfter",
                not_on_or_after
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(recipient) = &self.recipient {
            root.push_attribute(("Recipient", recipient.as_ref()));
        }
        if let Some(in_response_to) = &self.in_response_to {
            root.push_attribute(("InResponseTo", in_response_to.as_ref()));
        }
        if let Some(address) = &self.address {
            root.push_attribute(("Address", address.as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(content) = &self.content {
            writer.write_event(Event::Text(BytesText::from_plain_str(content.as_ref())))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(
            SUBJECT_CONFIRMATION_DATA_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
