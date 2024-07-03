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
        let v = self.to_vec()?;
        let output = std::str::from_utf8(v.as_slice())?.to_string();
        Ok(output)
    }

    fn to_vec(&'a self) -> Result<Vec<u8>, Self::Error> {
        let mut v = Vec::new();
        self.to_writer(Cursor::new(&mut v))?;
        Ok(v)
    }

    fn to_writer(&'a self, writer: impl std::io::Write) -> Result<(), Self::Error> {
        let mut xml_writer = Writer::new(writer);
        let e: Event<'a> = self.try_into()?;
        xml_writer.write_event(e)?;
        Ok(())
    }
}
