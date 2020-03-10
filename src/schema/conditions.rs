use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2:Conditions";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Conditions {
    #[serde(rename = "NotBefore")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: Option<DateTime<Utc>>,
    #[serde(rename = "AudienceRestriction", default)]
    pub audience_restrictions: Option<Vec<AudienceRestriction>>,
    #[serde(rename = "OneTimeUse")]
    pub one_time_use: Option<OneTimeUse>,
    #[serde(rename = "ProxyRestriction")]
    pub proxy_restriction: Option<ProxyRestriction>,
}

impl Conditions {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        if let Some(not_before) = &self.not_before {
            root.push_attribute((
                "NotBefore",
                not_before
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }
        if let Some(not_on_or_after) = &self.not_on_or_after {
            root.push_attribute((
                "NotOnOrAfter",
                not_on_or_after
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(audience_restrictions) = &self.audience_restrictions {
            for restriction in audience_restrictions {
                writer.write(restriction.to_xml()?.as_bytes())?;
            }
        }
        if let Some(proxy_restriction) = &self.proxy_restriction {
            writer.write(proxy_restriction.to_xml()?.as_bytes())?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

const AUDIENCE_RESTRICTION_NAME: &str = "saml2:AudienceRestriction";
const AUDIENCE_NAME: &str = "saml2:Audience";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AudienceRestriction {
    #[serde(rename = "Audience")]
    pub audience: Vec<String>,
}

impl AudienceRestriction {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::borrowed(
            AUDIENCE_RESTRICTION_NAME.as_bytes(),
            AUDIENCE_RESTRICTION_NAME.len(),
        );
        writer.write_event(Event::Start(root))?;
        for aud in &self.audience {
            writer.write_event(Event::Start(BytesStart::borrowed(
                AUDIENCE_NAME.as_bytes(),
                AUDIENCE_NAME.len(),
            )))?;
            writer.write_event(Event::Text(BytesText::from_plain_str(aud.as_ref())))?;
            writer.write_event(Event::End(BytesEnd::borrowed(AUDIENCE_NAME.as_bytes())))?;
        }
        writer.write_event(Event::End(BytesEnd::borrowed(
            AUDIENCE_RESTRICTION_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct OneTimeUse {}

const PROXY_RESTRICTION_NAME: &str = "saml2:ProxyRestriction";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProxyRestriction {
    #[serde(rename = "Count")]
    pub count: Option<usize>,
    #[serde(rename = "Audience")]
    pub audiences: Option<Vec<String>>,
}

impl ProxyRestriction {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(
            PROXY_RESTRICTION_NAME.as_bytes(),
            PROXY_RESTRICTION_NAME.len(),
        );
        if let Some(count) = &self.count {
            root.push_attribute(("Count", count.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(audiences) = &self.audiences {
            for aud in audiences {
                writer.write_event(Event::Start(BytesStart::borrowed(
                    AUDIENCE_NAME.as_bytes(),
                    AUDIENCE_NAME.len(),
                )))?;
                writer.write_event(Event::Text(BytesText::from_plain_str(aud.as_ref())))?;
                writer.write_event(Event::End(BytesEnd::borrowed(AUDIENCE_NAME.as_bytes())))?;
            }
        }
        writer.write_event(Event::End(BytesEnd::borrowed(
            PROXY_RESTRICTION_NAME.as_bytes(),
        )))?;
        Ok(String::from_utf8(write_buf)?)
    }
}
