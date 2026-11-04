//! Generate bindings from the same native package metadata used for linking.
use bindgen::Builder;
use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(xmlsec_dynamic)");
    println!("cargo:rustc-check-cfg=cfg(xmlsec_static)");
    println!("cargo:rerun-if-changed=bindings.h");
    if env::var_os("CARGO_FEATURE_XMLSEC").is_none() {
        return;
    }

    // The OpenSSL package selects a direct backend, including static Windows builds.
    // pkg-config preserves quoted paths and supplies platform-specific library names.
    let library = pkg_config::Config::new().probe("xmlsec1-openssl").expect(
        "Could not find xmlsec1-openssl using pkg-config; install XMLsec with the OpenSSL backend",
    );
    println!("cargo:rustc-cfg=xmlsec_static");
    let mut builder = Builder::default()
        .header("bindings.h")
        // Exclude unrelated C runtime functions pulled in by XMLsec headers.
        .allowlist_item("(xml|XML).*")
        .layout_tests(true)
        .generate_comments(true);
    for path in &library.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }
    for (name, value) in &library.defines {
        // Select direct OpenSSL even when the core library also supports plugins.
        if name != "XMLSEC_CRYPTO_DYNAMIC_LOADING" {
            builder = builder.clang_arg(match value {
                Some(value) => format!("-D{name}={value}"),
                None => format!("-D{name}"),
            });
        }
    }
    builder = builder.clang_arg("-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1");
    builder
        .generate()
        .expect("Unable to generate XMLsec bindings; libclang is required")
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("xmlsec_bindings.rs"))
        .expect("Could not write XMLsec bindings");
}
