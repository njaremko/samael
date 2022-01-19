use samael::{
    key_info::{KeyInfo, X509Data},
    metadata::{EntityDescriptor, IndexedEndpoint, KeyDescriptor, SpSsoDescriptor},
    utils::UtcDateTime,
};
use yaserde::ser::Config;

#[test]
fn test_sp_metadata() {
    let cert = X509Data { certificates: vec![String::from("MIIEQDCCAqgCCQDisA7Xfmj+5jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzANBgNVBAcMBkJvc3RvbjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGV0czEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20wHhcNMjAwMzA4MjI1NjQ3WhcNMzAwMzA2MjI1NjQ3WjBiMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzANBgNVBAcMBkJvc3RvbjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGV0czEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDYzvlEAZMce+J4j2YU++08SoTlKzrqKHOeV091yBfuemYlTi/Za01jRkP7fnSpaNx4R1hDtlAUP4thjjQQl3TEhFKrrug8NEzagPXphG6DELisDRE1/jXDeB/NFASrnflJ2IdkQzIUoNwMQfOmj27YKZ5eN06kjg1caTHSb7b8t7OMZYqf92PFwe8UmaUhBbyfGEFnHTwsLlLop7Qz6Ax8d/GSRagcz16Pl/5bW22pQS6EZ+XS5+71urjN90FiN+SnOnpxO3NMiwZLeQxVeeDW1s+Z7zp1uviiMDWcYp/GQroGGREsmXCS/tk/hYepmbKJGvjA4y2gIamvUwjuuuPvCIcnMiDur/KyQz5wPlUvc+FHXhJmjqOjyt+v3tbmlTRrd/OLU7kfWpN/KhKfUv/RtCxp8YWI0hor5FrAOie1xtTIMrXNSSrVSPBlO000BEQ3JMQytJWH/uHFv9KwGVMxBoN+PVGA2Si9oXxvBUTQ3G05V1cc2z8CwGDCWxo/TiMCAwEAATANBgkqhkiG9w0BAQsFAAOCAYEAxmOjjScYv8wGY5WOtVjtEa3fg9z8i4cDrWyJKOgsBbZLUj+DF4TtuEnQkAG4P6r953t1/L+BTUbA3E/7Mj+O2NJs33Er1McL1gw4uclk+gFtL5yEc5BLLgeXOGlnWyuRlTYZb40wDxS7QJoBM/rSXvGTuj4JhMuGTQTUFZ0P889OOPj8FxYOVHVfXLhWR9+17ip18ag/RCG6fJbd95OLV21F1E90yUIb8crEroLI+G0IAuvStqqWYHXqD/ONywvE/qun3CKqsoj+l5k6YCY/gwr936JZexviokhLS2o0gWppCtsxyQTGMJivK2sbvq60RNGvWHkOuVQ2XxGYgMFCgJFQwlD8UBiRdJ4T60i9N3DwwX3U2KKa5eskglvykQClHMrSlhYhyfoNdsDEt68ywyhltT+Q4Rqo09DRx7SbsSSqSpS0H2zxvYEY7NNeS/k993pRgQGscjfRYCGUbrfq4o5nS9531TKzsi7QluJNsaXpEYsdT9R+bmgyD26Ew7FD")] };
    let key_info = KeyInfo {
        x509_data: Some(cert),
        ..Default::default()
    };
    let key_descriptor1 = KeyDescriptor {
        key_info,
        key_use: Some(String::from("signing")),
        ..Default::default()
    };
    let cert = X509Data { certificates: vec![String::from("MIIEQDCCAqgCCQDisA7Xfmj+5jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzANBgNVBAcMBkJvc3RvbjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGV0czEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20wHhcNMjAwMzA4MjI1NjQ3WhcNMzAwMzA2MjI1NjQ3WjBiMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzANBgNVBAcMBkJvc3RvbjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGV0czEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDYzvlEAZMce+J4j2YU++08SoTlKzrqKHOeV091yBfuemYlTi/Za01jRkP7fnSpaNx4R1hDtlAUP4thjjQQl3TEhFKrrug8NEzagPXphG6DELisDRE1/jXDeB/NFASrnflJ2IdkQzIUoNwMQfOmj27YKZ5eN06kjg1caTHSb7b8t7OMZYqf92PFwe8UmaUhBbyfGEFnHTwsLlLop7Qz6Ax8d/GSRagcz16Pl/5bW22pQS6EZ+XS5+71urjN90FiN+SnOnpxO3NMiwZLeQxVeeDW1s+Z7zp1uviiMDWcYp/GQroGGREsmXCS/tk/hYepmbKJGvjA4y2gIamvUwjuuuPvCIcnMiDur/KyQz5wPlUvc+FHXhJmjqOjyt+v3tbmlTRrd/OLU7kfWpN/KhKfUv/RtCxp8YWI0hor5FrAOie1xtTIMrXNSSrVSPBlO000BEQ3JMQytJWH/uHFv9KwGVMxBoN+PVGA2Si9oXxvBUTQ3G05V1cc2z8CwGDCWxo/TiMCAwEAATANBgkqhkiG9w0BAQsFAAOCAYEAxmOjjScYv8wGY5WOtVjtEa3fg9z8i4cDrWyJKOgsBbZLUj+DF4TtuEnQkAG4P6r953t1/L+BTUbA3E/7Mj+O2NJs33Er1McL1gw4uclk+gFtL5yEc5BLLgeXOGlnWyuRlTYZb40wDxS7QJoBM/rSXvGTuj4JhMuGTQTUFZ0P889OOPj8FxYOVHVfXLhWR9+17ip18ag/RCG6fJbd95OLV21F1E90yUIb8crEroLI+G0IAuvStqqWYHXqD/ONywvE/qun3CKqsoj+l5k6YCY/gwr936JZexviokhLS2o0gWppCtsxyQTGMJivK2sbvq60RNGvWHkOuVQ2XxGYgMFCgJFQwlD8UBiRdJ4T60i9N3DwwX3U2KKa5eskglvykQClHMrSlhYhyfoNdsDEt68ywyhltT+Q4Rqo09DRx7SbsSSqSpS0H2zxvYEY7NNeS/k993pRgQGscjfRYCGUbrfq4o5nS9531TKzsi7QluJNsaXpEYsdT9R+bmgyD26Ew7FD")] };
    let key_info = KeyInfo {
        x509_data: Some(cert),
        ..Default::default()
    };
    let key_descriptor2 = KeyDescriptor {
        key_info,
        key_use: Some(String::from("encryption")),
        ..Default::default()
    };
    let acs = IndexedEndpoint {
        binding: String::from("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        location: String::from("https://sp.example.com/acs"),
        index: 1,
        ..Default::default()
    };
    let spsso = SpSsoDescriptor {
        key_descriptors: vec![key_descriptor1, key_descriptor2],
        name_id_formats: vec![String::from(
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        )],
        assertion_consumer_services: vec![acs],
        ..Default::default()
    };
    let descriptor = EntityDescriptor {
        valid_until: Some(UtcDateTime("2020-03-10T23:18:00Z".parse().unwrap())),
        cache_duration: Some(String::from("PT604800S")),
        entity_id: String::from("https://sp.example.com"),
        sp_sso_descriptors: vec![spsso],
        ..Default::default()
    };
    let config = Config {
        perform_indent: true,
        ..Default::default()
    };
    let descriptor_xml = yaserde::ser::to_string_with_config(&descriptor, &config).unwrap();
    let loaded_descriptor: EntityDescriptor = yaserde::de::from_str(&descriptor_xml).unwrap();
    assert_eq!(loaded_descriptor, descriptor);
}
