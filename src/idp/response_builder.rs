use crate::attribute::{Attribute, AttributeValue};
use crate::schema::{
    Assertion, AttributeStatement, AudienceRestriction, AuthnContext, AuthnContextClassRef,
    AuthnStatement, Conditions, Issuer, Response, Status, StatusCode, Subject, SubjectConfirmation,
    SubjectConfirmationData, SubjectNameID,
};
use crate::signature::Signature;
use chrono::Utc;

use super::{sp_extractor::RequiredAttribute, AuthenticationContextClass};
use crate::crypto;
use crate::idp::ResponseParams;

fn build_conditions(audience: &str) -> Conditions {
    Conditions {
        not_before: None,
        not_on_or_after: None,
        audience_restrictions: Some(vec![AudienceRestriction {
            audience: vec![audience.to_string()],
        }]),
        one_time_use: None,
        proxy_restriction: None,
    }
}

fn build_authn_statement(class: AuthenticationContextClass) -> AuthnStatement {
    AuthnStatement {
        authn_instant: Some(Utc::now()),
        session_index: None,
        session_not_on_or_after: None,
        subject_locality: None,
        authn_context: Some(AuthnContext {
            value: Some(AuthnContextClassRef {
                value: Some(class.to_string()),
            }),
        }),
    }
}

pub struct ResponseAttribute<'a> {
    pub required_attribute: RequiredAttribute,
    pub value: &'a str,
}

fn build_attributes(formats_names_values: &[ResponseAttribute]) -> Vec<Attribute> {
    formats_names_values
        .iter()
        .map(|attr| Attribute {
            friendly_name: None,
            name: Some(attr.required_attribute.name.clone()),
            name_format: attr.required_attribute.format.clone(),
            values: vec![AttributeValue {
                attribute_type: Some("xs:string".to_string()),
                value: Some(attr.value.to_string()),
            }],
        })
        .collect()
}

fn build_assertion(params: &ResponseParams)
    -> Assertion
{
    let ResponseParams {
        idp_x509_cert_der: _,
        subject_name_id,
        audience,
        acs_url,
        issuer,
        in_response_to_id,
        attributes,
        authentication_context,
        not_before,
        not_on_or_after,
    } = *params;

    let assertion_id = crypto::gen_saml_assertion_id();

    let attribute_statements = if attributes.is_empty() {
        None
    } else {
        Some(vec![
            AttributeStatement {
                attributes: build_attributes(attributes)
            }
        ])
    };

    Assertion {
        id: assertion_id,
        issue_instant: Utc::now(),
        version: "2.0".to_string(),
        issuer: Issuer {
            value: Some(issuer.to_string()),
            ..Default::default()
        },
        signature: None,
        subject: Some(Subject {
            name_id: Some(SubjectNameID {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                value: subject_name_id.to_string(),
            }),
            subject_confirmations: Some(vec![SubjectConfirmation {
                method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before,
                    not_on_or_after,
                    recipient: Some(acs_url.to_owned()),
                    in_response_to: Some(in_response_to_id.to_string()),
                    address: None,
                    content: None,
                }),
            }]),
        }),
        conditions: Some(build_conditions(audience)),
        authn_statements: Some(vec![build_authn_statement(authentication_context)]),
        attribute_statements,
    }
}

fn build_response(params: &ResponseParams) -> Response
{
    let issuer = Issuer {
        value: Some(params.issuer.to_string()),
        ..Default::default()
    };

    let response_id = crypto::gen_saml_response_id();

    Response {
        id: response_id.clone(),
        in_response_to: Some(params.in_response_to_id.to_owned()),
        version: "2.0".to_string(),
        issue_instant: Utc::now(),
        destination: Some(params.acs_url.to_string()),
        consent: None,
        issuer: Some(issuer),
        signature: Some(Signature::template(&response_id, params.idp_x509_cert_der)),
        status: Some(Status {
            status_code: StatusCode {
                value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string()),
            },
            status_message: None,
            status_detail: None,
        }),
        encrypted_assertion: None,
        assertion: Some(build_assertion(params)),
    }
}

pub fn build_response_template(params: &ResponseParams) -> Response
{
    build_response(params)
}
