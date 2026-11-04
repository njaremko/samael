use crate::metadata::helpers::write_plain_element;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
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

#[derive(Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ContactPerson {
    pub contact_type: Option<String>,
    pub company: Option<String>,
    pub given_name: Option<String>,
    pub sur_name: Option<String>,
    pub email_addresses: Option<Vec<String>>,
    pub telephone_numbers: Option<Vec<String>>,
}

impl<'de> serde::Deserialize<'de> for ContactPerson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct ContactPersonVisitor;

        impl<'de> Visitor<'de> for ContactPersonVisitor {
            type Value = ContactPerson;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ContactPerson element")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut contact_type = None;
                let mut company = None;
                let mut given_name = None;
                let mut sur_name = None;
                let mut email_addresses: Option<Vec<String>> = None;
                let mut telephone_numbers: Option<Vec<String>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "@contactType" => {
                            if contact_type.is_none() {
                                contact_type = Some(map.next_value()?);
                            } else {
                                // Skip duplicate (e.g. from namespaced remd:contactType)
                                map.next_value::<de::IgnoredAny>()?;
                            }
                        }
                        "Company" => {
                            company = Some(map.next_value()?);
                        }
                        "GivenName" => {
                            given_name = Some(map.next_value()?);
                        }
                        "SurName" => {
                            sur_name = Some(map.next_value()?);
                        }
                        "EmailAddress" => {
                            let val: String = map.next_value()?;
                            email_addresses.get_or_insert_with(Vec::new).push(val);
                        }
                        "TelephoneNumber" => {
                            let val: String = map.next_value()?;
                            telephone_numbers.get_or_insert_with(Vec::new).push(val);
                        }
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(ContactPerson {
                    contact_type,
                    company,
                    given_name,
                    sur_name,
                    email_addresses,
                    telephone_numbers,
                })
            }
        }

        deserializer.deserialize_map(ContactPersonVisitor)
    }
}

impl TryFrom<ContactPerson> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: ContactPerson) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ContactPerson> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &ContactPerson) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(contact_type) = &value.contact_type {
            root.push_attribute(("contactType", contact_type.as_ref()))
        }
        writer.write_event(Event::Start(root))?;

        value
            .company
            .as_ref()
            .map(|company| write_plain_element(&mut writer, "md:Company", company));
        value
            .sur_name
            .as_ref()
            .map(|sur_name| write_plain_element(&mut writer, "md:SurName", sur_name));
        value
            .given_name
            .as_ref()
            .map(|given_name| write_plain_element(&mut writer, "md:GivenName", given_name));

        if let Some(email_addresses) = &value.email_addresses {
            for email in email_addresses {
                write_plain_element(&mut writer, "md:EmailAddress", email)?;
            }
        }

        if let Some(telephone_numbers) = &value.telephone_numbers {
            for number in telephone_numbers {
                write_plain_element(&mut writer, "md:TelephoneNumber", number)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
