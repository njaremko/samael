use crate::metadata::{LocalizedName, LocalizedUri};
use quick_xml::events::{BytesEnd, BytesStart, Event};
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

impl Organization {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        writer.write_event(Event::Start(root))?;
        if let Some(organization_names) = &self.organization_names {
            for name in organization_names {
                writer.write(name.to_xml("md:OrganizationName")?.as_bytes())?;
            }
        }
        if let Some(organization_display_names) = &self.organization_display_names {
            for name in organization_display_names {
                writer.write(name.to_xml("md:OrganizationDisplayName")?.as_bytes())?;
            }
        }
        if let Some(organization_urls) = &self.organization_urls {
            for url in organization_urls {
                writer.write(url.to_xml("md:OrganizationURL")?.as_bytes())?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
