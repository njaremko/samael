pub mod attribute;
pub mod key_info;
pub mod metadata;
pub mod schema;
pub mod service_provider;
pub mod idp;
pub mod signature;
pub mod crypto;
mod xmlsec;
mod bindings;

#[macro_use]
extern crate derive_builder;


pub fn init() -> xmlsec::XmlSecResult<xmlsec::XmlSecContext> {
    xmlsec::XmlSecContext::new()
}