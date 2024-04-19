use crate::schema::{AuthnContextClassRef, AuthnContextDeclRef};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;
use std::str::FromStr;

const NAME: &str = "saml2p:RequestedAuthnContext";
const SCHEMA: (&str, &str) = ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedAuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    pub authn_context_class_refs: Option<Vec<AuthnContextClassRef>>,
    #[serde(rename = "AuthnContextDeclRef")]
    pub authn_context_decl_refs: Option<Vec<AuthnContextDeclRef>>,
    #[serde(rename = "@Comparison")]
    pub comparison: Option<AuthnContextComparison>,
}

impl TryFrom<RequestedAuthnContext> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: RequestedAuthnContext) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&RequestedAuthnContext> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RequestedAuthnContext) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::from_content(NAME, NAME.len());
        root.push_attribute(SCHEMA);

        if let Some(comparison) = &value.comparison {
            root.push_attribute(("Comparison", comparison.value()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(authn_context_class_refs) = &value.authn_context_class_refs {
            for authn_context_class_ref in authn_context_class_refs {
                let event: Event<'_> = authn_context_class_ref.try_into()?;
                writer.write_event(event)?;
            }
        } else if let Some(authn_context_decl_refs) = &value.authn_context_decl_refs {
            for authn_context_decl_ref in authn_context_decl_refs {
                let event: Event<'_> = authn_context_decl_ref.try_into()?;
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
#[serde(rename_all = "lowercase")]
pub enum AuthnContextComparison {
    Exact,
    Minimum,
    Maximum,
    Better,
}

impl AuthnContextComparison {
    pub fn value(&self) -> &'static str {
        match self {
            AuthnContextComparison::Exact => "exact",
            AuthnContextComparison::Minimum => "minimum",
            AuthnContextComparison::Maximum => "maximum",
            AuthnContextComparison::Better => "better",
        }
    }
}

impl FromStr for AuthnContextComparison {
    type Err = quick_xml::DeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "exact" => AuthnContextComparison::Exact,
            "minimum" => AuthnContextComparison::Minimum,
            "maximum" => AuthnContextComparison::Maximum,
            "better" => AuthnContextComparison::Better,
            _ => {
                return Err(quick_xml::DeError::Custom("Illegal comparison! Must be one of `exact`, `minimum`, `maximum` or `better`".to_string()));
            }
        })
    }
}

#[cfg(test)]
mod test {
    use crate::traits::ToXml;

    use super::*;

    #[test]
    pub fn test_deserialize_serialize_requested_authn_context() {
        let xml_context = r#"<saml2p:RequestedAuthnContext xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Comparison="exact"><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2p:RequestedAuthnContext>"#;

        let expected_context: RequestedAuthnContext = quick_xml::de::from_str(xml_context)
            .expect("failed to parse RequestedAuthnContext");
        let serialized_context = expected_context
            .to_xml()
            .expect("failed to convert RequestedAuthnContext to xml");
        let actual_context: RequestedAuthnContext = quick_xml::de::from_str(&serialized_context)
            .expect("failed to re-parse RequestedAuthnContext");

        assert_eq!(expected_context, actual_context);
    }
}
