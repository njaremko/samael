use crate::metadata::{LocalizedName, LocalizedUri};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "md:Organization";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Organization {
    #[serde(rename = "OrganizationName")]
    pub organization_names: Option<Vec<LocalizedName>>,
    #[serde(rename = "OrganizationDisplayName")]
    pub organization_display_names: Option<Vec<LocalizedName>>,
    #[serde(rename = "md:OrganizationURL")]
    pub organization_urls: Option<Vec<LocalizedUri>>,
}

impl TryFrom<&Organization> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Organization) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(NAME);
        writer.write_event(Event::Start(root))?;
        if let Some(organization_names) = &value.organization_names {
            for name in organization_names {
                writer.write_event(name.to_xml("md:OrganizationName")?)?;
            }
        }
        if let Some(organization_display_names) = &value.organization_display_names {
            for name in organization_display_names {
                writer.write_event(name.to_xml("md:OrganizationDisplayName")?)?;
            }
        }
        if let Some(organization_urls) = &value.organization_urls {
            for url in organization_urls {
                writer.write_event(url.to_xml("md:OrganizationURL")?)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
