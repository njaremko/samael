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

#[allow(unused)]
pub fn write_plain_attribute<W: Write>(
    writer: &mut BytesStart,
    attribute: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.push_attribute((attribute, text));
    Ok(())
}
