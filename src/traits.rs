use quick_xml::{events::Event, Writer};
use std::{fmt::Debug, io::Cursor, str::Utf8Error};

pub trait ToXml<'a> {
    type Error;

    fn to_string(&'a self) -> Result<String, Self::Error>;
    fn to_vec(&'a self) -> Result<Vec<u8>, Self::Error>;
    fn to_writer(&'a self, writer: impl std::io::Write) -> Result<(), Self::Error>;
}

impl<'a, FromType> ToXml<'a> for FromType
where
    &'a FromType: TryInto<Event<'a>> + 'a,
    <&'a FromType as TryInto<Event<'a>>>::Error: Debug + From<quick_xml::Error> + From<Utf8Error>,
{
    type Error = <&'a FromType as TryInto<Event<'a>>>::Error;

    fn to_string(&'a self) -> Result<String, Self::Error> {
        let mut v = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut v));
        let e: Event<'a> = self.try_into()?;
        writer.write_event(e)?;
        let output = std::str::from_utf8(v.as_slice())?.to_string();
        Ok(output)
    }

    fn to_vec(&'a self) -> Result<Vec<u8>, Self::Error> {
        let mut v = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut v));
        let e: Event<'a> = self.try_into()?;
        writer.write_event(e)?;
        Ok(v)
    }

    fn to_writer(&'a self, writer: impl std::io::Write) -> Result<(), Self::Error> {
        let mut writer = Writer::new(writer);
        let e: Event<'a> = self.try_into()?;
        writer.write_event(e)?;
        Ok(())
    }
}
