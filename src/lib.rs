pub mod attribute;
#[cfg(feature = "xmlsec")]
mod bindings;
pub mod crypto;
#[cfg(feature = "xmlsec")]
pub mod idp;
pub mod key_info;
pub mod metadata;
pub mod schema;
#[cfg(feature = "xmlsec")]
pub mod service_provider;
pub mod signature;
#[cfg(feature = "xmlsec")]
mod xmlsec;
#[cfg(feature = "xmlsec")]
pub use xmlsec::XmlSecError;

pub mod traits;

#[macro_use]
extern crate derive_builder;

#[cfg(feature = "xmlsec")]
pub fn init() -> xmlsec::XmlSecResult<xmlsec::XmlSecContext> {
    xmlsec::XmlSecContext::new()
}
