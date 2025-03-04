## Samael

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/samael.svg
[crates-url]: https://crates.io/crates/samael
[mit-badge]: https://img.shields.io/crates/l/samael
[mit-url]: https://github.com/njaremko/samael/blob/master/LICENSE

This is a SAML2 library for rust.

This is a work in progress. Pull Requests are welcome.

Current Features:

- Serializing and Deserializing SAML messages
- IDP-initiated SSO
- SP-initiated SSO Redirect-POST binding
- Helpers for validating SAML assertions
  - Encrypted assertions only support:
    - **key info:**
      - `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`
      - `http://www.w3.org/2001/04/xmlenc#rsa-1_5`
    - **value info:**
      - `http://www.w3.org/2001/04/xmlenc#aes128-cbc`
      - `http://www.w3.org/2009/xmlenc11#aes128-gcm`
- Verify SAMLRequest (AuthnRequest) message signatures
- Create signed SAMLResponse (Response) messages

The `"xmlsec"` feature flag adds basic support for verifying and signing SAML messages. We're using a modified copy of [rust-xmlsec](https://github.com/voipir/rust-xmlsec) library (bindings to xmlsec1 library).

If you want to use the `"xmlsec"` feature, you'll need to install the following C libs:

- libiconv
- libtool
- libxml2
- libxslt
- libclang
- openssl
- pkg-config
- xmlsec1

# Build instructions

We use [nix](https://nixos.org) to faciliate reproducible builds of `samael`.
It will ensure you have the required libraries installed in a way that won't cause any issues with the rest of your system.
If you want to take advantage of this, you'll need to put in a little bit of work.

1. [Install nix](https://github.com/DeterminateSystems/nix-installer)
1. Install [direnv](https://direnv.net/) and [cachix](https://docs.cachix.org)
   ```
   # Add ~/.nix-profile/bin to your path first
   nix profile install nixpkgs#direnv
   nix profile install nixpkgs#cachix
   ```
1. Run `cachix use nix-community` to enable a binary cache for the rust toolchain (otherwise you'll build the rust toolchain from scratch)
1. `cd` into this repo and run `direnv allow` and `nix-direnv-reload`
1. Install the [direnv VS Code extension](https://marketplace.visualstudio.com/items?itemName=mkhl.direnv)

## Building the library

Just run `nix build`

## Entering a dev environment

If you followed the above instructions, just `cd`-ing into the directory will setup a reproducible dev environment,
but if you don't want to install `direnv`, then just run `nix develop`.

From their you can build as normal:

```sh
cargo build --features xmlsec
cargo test --features xmlsec
```

# How do I use this library?

You'll need these dependencies for this example

```toml
[dependencies]
tokio = { version = "1.28.1", features = ["full"] }
samael = { version = "0.0.12", features = ["xmlsec"] }
warp = "0.3.5"
reqwest = "0.11.18"
openssl = "0.10.52"
openssl-probe = "0.1.5"
```

Here is some sample code using this library:

```rust
use samael::metadata::{ContactPerson, ContactType, EntityDescriptor};
use samael::service_provider::ServiceProviderBuilder;
use std::collections::HashMap;
use std::fs;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    openssl_probe::init_ssl_cert_env_vars();

    let resp = reqwest::get("https://samltest.id/saml/idp")
        .await?
        .text()
        .await?;
    let idp_metadata: EntityDescriptor = samael::metadata::de::from_str(&resp)?;

    let pub_key = openssl::x509::X509::from_pem(&fs::read("./publickey.cer")?)?;
    let private_key = openssl::rsa::Rsa::private_key_from_pem(&fs::read("./privatekey.pem")?)?;

    let sp = ServiceProviderBuilder::default()
        .entity_id("".to_string())
        .key(private_key)
        .certificate(pub_key)
        .allow_idp_initiated(true)
        .contact_person(ContactPerson {
            sur_name: Some("Bob".to_string()),
            contact_type: Some(ContactType::Technical.value().to_string()),
            ..ContactPerson::default()
        })
        .idp_metadata(idp_metadata)
        .acs_url("http://localhost:8080/saml/acs".to_string())
        .slo_url("http://localhost:8080/saml/slo".to_string())
        .build()?;

    let metadata = sp.metadata()?.to_string()?;

    let metadata_route = warp::get()
        .and(warp::path("metadata"))
        .map(move || metadata.clone());

    let acs_route = warp::post()
        .and(warp::path("acs"))
        .and(warp::body::form())
        .map(move |s: HashMap<String, String>| {
            if let Some(encoded_resp) = s.get("SAMLResponse") {
                let t = sp
                    .parse_base64_response(encoded_resp, Some(&["a_possible_request_id"]))
                    .unwrap();
                return format!("{:?}", t);
            }
            format!("")
        });

    let saml_routes = warp::path("saml").and(acs_route.or(metadata_route));
    warp::serve(saml_routes).run(([127, 0, 0, 1], 8080)).await;
    Ok(())
}
```
