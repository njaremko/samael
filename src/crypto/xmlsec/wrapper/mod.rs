//
// Source of wrapper adapted from a separate project: https://github.com/voipir/rust-xmlsec
// MIT Licence (Voipir Group): https://github.com/voipir/rust-xmlsec/blob/master/LICENSE

//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]

#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;

mod backend;
mod bindings;
mod error;
mod keys;
mod xmldsig;
mod xmlsec_internal;

// exports
pub use self::bindings::XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES;
pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;
pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyFormat;
pub use self::xmldsig::VerifiedReference;
pub use self::xmldsig::XmlSecSignatureContext;
