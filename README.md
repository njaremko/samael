## Samael

This is a SAML2 library for rust.

This is a work in progress. Pull Requests are welcome.

Current Features:
- Serializing and Deserializing SAML messages
- Helpers for validating SAML assertions
    - Encrypted assertions aren't supported yet
    - SAMLResponse signatures aren't validated yet
    
Priority right now is correctness, then I'll revisit usability.
    
Here is some saml code using this library:
```rust
use samael::metadata::{ContactPerson, ContactType, LocalizedName, LocalizedUri, Organization};
use samael::service_provider::ServiceProvider;
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
    let pub_key = openssl::x509::X509::from_pem(&fs::read("./publickey.cer")?)?;
    let private_key = openssl::rsa::Rsa::private_key_from_pem(&fs::read("./privatekey.pem")?)?;
    let sp = ServiceProvider {
        entity_id: Some("nid-1234".to_string()),
        key: Some(private_key),
        certificate: Some(pub_key),
        allow_idp_initiated: true,
        contact_person: Some(ContactPerson {
            sur_name: Some("Bob".to_string()),
            contact_type: Some(ContactType::Technical.value().to_string()),
            ..ContactPerson::default()
        }),
        idp_metadata: samael::metadata::de::from_str(&resp)?,
        acs_url: Some("http://localhost:8080/saml/acs".to_string()),
        slo_url: Some("http://localhost:8080/saml/slo".to_string()),
        ..ServiceProvider::default()
    };

    let mut metadata = sp.metadata()?;
    metadata.organization = Some(Organization {
        organization_names: Some(vec![LocalizedName {
            lang: "en".to_string(),
            value: "https://google.com".to_string(),
        }]),
        organization_display_names: Some(vec![LocalizedName {
            lang: "en".to_string(),
            value: "https://google.com".to_string(),
        }]),
        organization_urls: Some(vec![LocalizedUri {
            lang: "en".to_string(),
            value: "https://google.com".to_string(),
        }]),
        ..Organization::default()
    });

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
                    .parse_response(encoded_resp, &["test".to_string()])
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