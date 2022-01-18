use crate::metadata::helpers::write_plain_element;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:ContactPerson";

pub enum ContactType {
    Technical,
    Support,
    Administrative,
    Billing,
    Other,
}

impl ContactType {
    pub fn value(&self) -> &'static str {
        match self {
            ContactType::Technical => "technical",
            ContactType::Support => "support",
            ContactType::Administrative => "administrative",
            ContactType::Billing => "billing",
            ContactType::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ContactPerson {
    #[serde(rename = "contactType")]
    pub contact_type: Option<String>,
    #[serde(rename = "Company")]
    pub company: Option<String>,
    #[serde(rename = "GivenName")]
    pub given_name: Option<String>,
    #[serde(rename = "SurName")]
    pub sur_name: Option<String>,
    #[serde(rename = "EmailAddress")]
    pub email_addresses: Option<Vec<String>>,
    #[serde(rename = "TelephoneNumber")]
    pub telephone_numbers: Option<Vec<String>>,
}

impl ContactPerson {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(contact_type) = &self.contact_type {
            root.push_attribute(("contactType", contact_type.as_ref()))
        }
        writer.write_event(Event::Start(root))?;

        self.company
            .as_ref()
            .map(|company| write_plain_element(&mut writer, "md:Company", company));
        self.sur_name
            .as_ref()
            .map(|sur_name| write_plain_element(&mut writer, "md:SurName", sur_name));
        self.given_name
            .as_ref()
            .map(|given_name| write_plain_element(&mut writer, "md:GivenName", given_name));

        if let Some(email_addresses) = &self.email_addresses {
            for email in email_addresses {
                write_plain_element(&mut writer, "md:EmailAddress", email)?;
            }
        }

        if let Some(telephone_numbers) = &self.telephone_numbers {
            for number in telephone_numbers {
                write_plain_element(&mut writer, "md:TelephoneNumber", number)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
