## Samael

This is a SAML2 library for rust.

This is a work in progress. Pull Requests are welcome.

Current Features:
- Serializing and Deserializing SAML messages
- IDP-initiated SSO
- SP-initiated SSO Redirect-POST binding 
- Helpers for validating SAML assertions
    - Encrypted assertions aren't supported yet
- Verify SAMLRequest (AuthnRequest) message signatures
- Create signed SAMLResponse (Response) messages

The `"xmlsec"` feature flag adds basic support for verifying and signing SAML messages. We're using a modified copy of [rust-xmlsec](https://github.com/voipir/rust-xmlsec) library (bindings to xmlsec1 library).

If you want to use the `"xmlsec"` feature, you'll need to install the following C libs:
- libxml2
- openssl
- xmlsec1 (with openssl statically linked)
> **NOTE**: this has only been tested using libxml2 ^2.9.10. 
> The default macOS libxml2 (2.9.4) has known concurrency issues.
    
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

    let metadata = sp.metadata()?.to_xml()?;

    let metadata_route = warp::get()
        .and(warp::path("metadata"))
        .map(move || metadata.clone());

    let acs_route = warp::post()
        .and(warp::path("acs"))
        .and(warp::body::form())
        .map(move |s: HashMap<String, String>| {
            if let Some(encoded_resp) = s.get("SAMLResponse") {
                let t = sp
                    .parse_response(encoded_resp, &["a_possible_request_id".to_string()])
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
