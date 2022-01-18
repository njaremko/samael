use crate::metadata::{LocalizedName, LocalizedUri};
use crate::ToXml;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Write;

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

impl ToXml for Organization {
    fn to_xml<W: Write>(&self, writer: &mut Writer<W>) -> Result<(), Box<dyn std::error::Error>> {
        let root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        writer.write_event(Event::Start(root))?;
        if let Some(organization_names) = &self.organization_names {
            for name in organization_names {
                name.to_xml(writer, "md:OrganizationName")?;
            }
        }
        if let Some(organization_display_names) = &self.organization_display_names {
            for name in organization_display_names {
                name.to_xml(writer, "md:OrganizationDisplayName")?;
            }
        }
        if let Some(organization_urls) = &self.organization_urls {
            for url in organization_urls {
                url.to_xml(writer, "md:OrganizationURL")?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(())
    }
}
