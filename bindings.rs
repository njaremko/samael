//!
//! XmlSec Bindings Generation
//!
use bindgen::Builder as BindgenBuilder;

use pkg_config::Config as PkgConfig;

use std::env;
use std::path::PathBuf;
use std::process::Command;

const BINDINGS: &str = "bindings.rs";

fn main() {
    if env::var_os("CARGO_FEATURE_XMLSEC").is_some() {
        println!("cargo:rustc-link-lib=xmlsec1-openssl"); // -lxmlsec1-openssl
        println!("cargo:rustc-link-lib=xmlsec1"); // -lxmlsec1
        println!("cargo:rustc-link-lib=xml2"); // -lxml2
        println!("cargo:rustc-link-lib=ssl"); // -lssl
        println!("cargo:rustc-link-lib=crypto"); // -lcrypto

        let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let path_bindings = path_out.join(BINDINGS);

        if !path_bindings.exists() {
            PkgConfig::new()
                .probe("xmlsec1")
                .expect("Could not find xmlsec1 using pkg-config");

            let bindbuild = BindgenBuilder::default()
                .header("bindings.h")
                .clang_args(fetch_xmlsec_config_flags())
                .clang_args(fetch_xmlsec_config_libs())
                .layout_tests(false)
                .rustfmt_bindings(true)
                .generate_comments(true);

            let bindings = bindbuild.generate().expect("Unable to generate bindings");

            bindings
                .write_to_file(path_bindings)
                .expect("Couldn't write bindings!");
        }
    }
}

fn fetch_xmlsec_config_flags() -> Vec<String> {
    let out = Command::new("xmlsec1-config")
        .arg("--cflags")
        .output()
        .expect("Failed to get --cflags from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}

fn fetch_xmlsec_config_libs() -> Vec<String> {
    let out = Command::new("xmlsec1-config")
        .arg("--libs")
        .output()
        .expect("Failed to get --libs from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}

fn args_from_output(args: Vec<u8>) -> Vec<String> {
    let decoded = String::from_utf8(args).expect("Got invalid UTF8 from xmlsec1-config");

    decoded.split_whitespace().map(|p| p.to_owned()).collect()
}
