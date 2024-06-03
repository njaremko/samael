use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml2:Conditions";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into, strip_option))]
pub struct Conditions {
    #[serde(rename = "@NotBefore")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(rename = "@NotOnOrAfter")]
    pub not_on_or_after: Option<DateTime<Utc>>,
    #[serde(rename = "AudienceRestriction", default)]
    pub audience_restrictions: Option<Vec<AudienceRestriction>>,
    #[serde(rename = "OneTimeUse")]
    pub one_time_use: Option<OneTimeUse>,
    #[serde(rename = "ProxyRestriction")]
    pub proxy_restriction: Option<ProxyRestriction>,
}

impl TryFrom<Conditions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Conditions) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Conditions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Conditions) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(not_before) = &value.not_before {
            root.push_attribute((
                "NotBefore",
                not_before
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }
        if let Some(not_on_or_after) = &value.not_on_or_after {
            root.push_attribute((
                "NotOnOrAfter",
                not_on_or_after
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(audience_restrictions) = &value.audience_restrictions {
            for restriction in audience_restrictions {
                let event: Event<'_> = restriction.try_into()?;
                writer.write_event(event)?;
            }
        }
        if let Some(proxy_restriction) = &value.proxy_restriction {
            let event: Event<'_> = proxy_restriction.try_into()?;
            writer.write_event(event)?;
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const AUDIENCE_RESTRICTION_NAME: &str = "saml2:AudienceRestriction";
const AUDIENCE_NAME: &str = "saml2:Audience";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AudienceRestriction {
    #[serde(rename = "Audience")]
    pub audience: Vec<String>,
}

impl TryFrom<AudienceRestriction> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AudienceRestriction) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AudienceRestriction> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AudienceRestriction) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(AUDIENCE_RESTRICTION_NAME);
        writer.write_event(Event::Start(root))?;
        for aud in &value.audience {
            writer.write_event(Event::Start(BytesStart::new(AUDIENCE_NAME)))?;
            writer.write_event(Event::Text(BytesText::from_escaped(aud)))?;
            writer.write_event(Event::End(BytesEnd::new(AUDIENCE_NAME)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(AUDIENCE_RESTRICTION_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct OneTimeUse {}

const PROXY_RESTRICTION_NAME: &str = "saml2:ProxyRestriction";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProxyRestriction {
    #[serde(rename = "@Count")]
    pub count: Option<usize>,
    #[serde(rename = "Audience")]
    pub audiences: Option<Vec<String>>,
}

impl TryFrom<ProxyRestriction> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: ProxyRestriction) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ProxyRestriction> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &ProxyRestriction) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(PROXY_RESTRICTION_NAME);
        if let Some(count) = &value.count {
            root.push_attribute(("Count", count.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(audiences) = &value.audiences {
            for aud in audiences {
                writer.write_event(Event::Start(BytesStart::new(AUDIENCE_NAME)))?;
                writer.write_event(Event::Text(BytesText::from_escaped(aud)))?;
                writer.write_event(Event::End(BytesEnd::new(AUDIENCE_NAME)))?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(PROXY_RESTRICTION_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
