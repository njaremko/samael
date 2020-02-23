use crate::metadata::EntityDescriptor;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Write;

pub fn write_plain_element<W: Write>(
    writer: &mut Writer<W>,
    element_name: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let element = BytesStart::borrowed(element_name.as_bytes(), element_name.len());
    writer.write_event(Event::Start(element))?;
    writer.write_event(Event::Text(BytesText::from_plain_str(text)))?;
    writer.write_event(Event::End(BytesEnd::borrowed(element_name.as_bytes())))?;
    Ok(())
}

pub fn write_plain_attribute<W: Write>(
    writer: &mut BytesStart,
    attribute: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.push_attribute((attribute, text));
    Ok(())
}

pub async fn fetch_metadata(
    client: &reqwest::Client,
    metadata_url: url::Url,
) -> Result<EntityDescriptor, Box<dyn std::error::Error>> {
    let res: reqwest::Response = client.get(metadata_url).send().await?;
    let r: EntityDescriptor = quick_xml::de::from_str(&res.text().await?)?;
    Ok(r)
}
