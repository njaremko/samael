use std::io::{Read, Write};

use chrono::{DateTime, SecondsFormat, Utc};
use yaserde::xml;
use yaserde::{YaDeserialize, YaSerialize};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct UtcDateTime(pub DateTime<Utc>);

impl Default for UtcDateTime {
    fn default() -> Self {
        Self(Utc::now())
    }
}

impl YaDeserialize for UtcDateTime {
    fn deserialize<R: Read>(reader: &mut yaserde::de::Deserializer<R>) -> Result<Self, String> {
        match (
            reader.next_event()?,
            reader.next_event()?,
            reader.next_event()?,
        ) {
            (
                xml::reader::XmlEvent::StartElement { .. },
                xml::reader::XmlEvent::Characters(s),
                xml::reader::XmlEvent::EndElement { .. },
            ) => Ok(UtcDateTime(
                s.parse().map_err(|e: chrono::ParseError| e.to_string())?,
            )),
            _ => Err("Malformed RFC3339 time attribute".to_string()),
        }
    }
}

impl YaSerialize for UtcDateTime {
    fn serialize<W: Write>(&self, writer: &mut yaserde::ser::Serializer<W>) -> Result<(), String> {
        writer
            .write(xml::writer::XmlEvent::Characters(
                &self.0.to_rfc3339_opts(SecondsFormat::Millis, true),
            ))
            .map_err(|e| e.to_string())
    }

    fn serialize_attributes(
        &self,
        attributes: Vec<xml::attribute::OwnedAttribute>,
        namespace: xml::namespace::Namespace,
    ) -> Result<
        (
            Vec<xml::attribute::OwnedAttribute>,
            xml::namespace::Namespace,
        ),
        String,
    > {
        Ok((attributes, namespace))
    }
}
