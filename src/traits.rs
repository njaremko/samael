use quick_xml::{events::Event, Writer};
use std::{fmt::Debug, io::Cursor, str::Utf8Error};

pub trait ToXml<'a> {
    type Error;

    fn to_xml(&'a self) -> Result<String, Self::Error>;
}

impl<'a, FromType> ToXml<'a> for FromType
where
    FromType: TryInto<Event<'a>> + Clone,
    FromType::Error: Debug + From<quick_xml::Error> + From<Utf8Error>,
{
    type Error = FromType::Error;

    fn to_xml(&'a self) -> Result<String, Self::Error> {
        let mut v = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut v));
        let e: Event<'a> = self.clone().try_into()?;
        writer.write_event(e)?;
        let output = std::str::from_utf8(v.as_slice())?.to_string();
        Ok(output)
    }
}
