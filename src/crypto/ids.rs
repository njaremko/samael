pub fn gen_saml_response_id() -> String {
    format!("id{}", uuid::Uuid::new_v4())
}

pub fn gen_saml_assertion_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
}

