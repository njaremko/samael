//
// Source of xmlsec adapted from a separate project: https://github.com/voipir/rust-xmlsec
// MIT Licence (Voipir Group): https://github.com/voipir/rust-xmlsec/blob/master/LICENSE

//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]

#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;
#[doc(hidden)]
pub use libxml::tree::node::Node as XmlNode;

mod error;
mod keys;
mod xmldsig;
#[allow(clippy::module_inception)]
mod xmlsec;

// exports
pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;
pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyFormat;
pub use self::xmldsig::XmlSecSignatureContext;
pub use self::xmlsec::XmlSecContext;
