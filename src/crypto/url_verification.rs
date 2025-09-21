use crate::signature::SignatureAlgorithm;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum UrlVerifierError {
    #[error("Unimplemented SigAlg: {:?}", sigalg)]
    SigAlgUnimplemented { sigalg: String },
}

pub struct UrlVerifier {
    public_key: openssl::pkey::PKey<openssl::pkey::Public>,
}

impl UrlVerifier {
    pub fn from_rsa_pem(public_key_pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let public = openssl::rsa::Rsa::public_key_from_pem(public_key_pem)?;
        let public_key = openssl::pkey::PKey::from_rsa(public)?;
        Ok(Self { public_key })
    }

    pub fn from_rsa_der(public_key_der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let public = openssl::rsa::Rsa::public_key_from_der(public_key_der)?;
        let public_key = openssl::pkey::PKey::from_rsa(public)?;
        Ok(Self { public_key })
    }

    pub fn from_ec_pem(public_key_pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let public = openssl::ec::EcKey::public_key_from_pem(public_key_pem)?;
        let public_key = openssl::pkey::PKey::from_ec_key(public)?;
        Ok(Self { public_key })
    }

    pub fn from_ec_der(public_key_der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let public = openssl::ec::EcKey::public_key_from_der(public_key_der)?;
        let public_key = openssl::pkey::PKey::from_ec_key(public)?;
        Ok(Self { public_key })
    }

    pub fn from_x509_cert_pem(public_cert_pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let x509 = openssl::x509::X509::from_pem(public_cert_pem.as_bytes())?;
        let public_key = x509.public_key()?;
        Ok(Self { public_key })
    }

    pub fn from_x509(
        public_cert: &openssl::x509::X509,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let public_key = public_cert.public_key()?;
        Ok(Self { public_key })
    }

    // Signed url should look like:
    //
    //   http://idp.example.com/SSOService.php?SAMLRequest=...&SigAlg=...&Signature=...
    //
    // Only want to verify the percent encoded non-Signature portion:
    //
    //   http://idp.example.com/SSOService.php?SAMLRequest=...&SigAlg=...&Signature=...
    //                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^

    pub fn verify_signed_request_url(
        &self,
        signed_request_url: &url::Url,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.verify_signed_url(
            signed_request_url,
            &["SAMLRequest".into(), "RelayState".into(), "SigAlg".into()],
        )
    }

    pub fn verify_signed_response_url(
        &self,
        signed_response_url: &url::Url,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.verify_signed_url(
            signed_response_url,
            &["SAMLResponse".into(), "RelayState".into(), "SigAlg".into()],
        )
    }

    pub fn verify_percent_encoded_request_uri_string(
        &self,
        percent_encoded_uri_string: &String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // percent encoded URI:
        //   /saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        // convert to a URL, then use verify_request_url
        let signed_request_url: url::Url =
            format!("http://dummy.fake{}", percent_encoded_uri_string).parse()?;

        self.verify_signed_request_url(&signed_request_url)
    }

    pub fn verify_percent_encoded_response_uri_string(
        &self,
        percent_encoded_uri_string: &String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // percent encoded URI:
        //   /saml?SAMLResponse=..&SigAlg=..&Signature=..
        //
        // convert to a URL, then use verify_response_url
        let signed_response_url: url::Url =
            format!("http://dummy.fake{}", percent_encoded_uri_string).parse()?;

        self.verify_signed_response_url(&signed_response_url)
    }

    fn verify_signed_url(
        &self,
        signed_url: &url::Url,
        query_keys: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Collect query params from URL
        let query_params = signed_url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();

        // Match against implemented SigAlg
        let sig_alg = SignatureAlgorithm::from_str(&query_params["SigAlg"])?;
        if let SignatureAlgorithm::Unsupported(sigalg) = sig_alg {
            return Err(Box::new(UrlVerifierError::SigAlgUnimplemented { sigalg }));
        }

        // Construct a Url so that percent encoded query can be easily
        // constructed.
        let mut verify_url = url::Url::parse(
            format!(
                "{}://{}",
                signed_url.scheme(),
                signed_url.host_str().unwrap(),
            )
            .as_str(),
        )?;

        // Section 3.4.4.1 of
        // https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf:
        //
        // To construct the signature, a string consisting of the concatenation
        // of the RelayState (if present), SigAlg, and SAMLRequest (or
        // SAMLResponse) query string parameters (each one URL- encoded) is
        // constructed in one of the following ways (ordered as below):
        //
        //   SAMLRequest=value&RelayState=value&SigAlg=value
        //   SAMLResponse=value&RelayState=value&SigAlg=value
        //
        // Order matters!
        for key in query_keys {
            if query_params.contains_key(key) {
                verify_url
                    .query_pairs_mut()
                    .append_pair(key, &query_params[key]);
            }
        }

        let signed_string: String = verify_url.query().unwrap().to_string();
        let signature = general_purpose::STANDARD.decode(&query_params["Signature"])?;

        self.verify_signature(signed_string.as_bytes(), sig_alg, &signature)
    }

    fn verify_signature(
        &self,
        data: &[u8],
        sig_alg: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut verifier = openssl::sign::Verifier::new(
            match sig_alg {
                SignatureAlgorithm::RsaSha256 => openssl::hash::MessageDigest::sha256(),
                SignatureAlgorithm::EcdsaSha256 => openssl::hash::MessageDigest::sha256(),
                _ => panic!("sig_alg is bad!"),
            },
            &self.public_key,
        )?;

        verifier.update(data)?;

        Ok(verifier.verify(signature)?)
    }
}

#[cfg(test)]
mod test {
    use super::UrlVerifier;
    use crate::service_provider::ServiceProvider;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_verify_uri() {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let idp_metadata_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_2_metadata.xml"
        ));

        let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
        let max_issue_delay = Utc::now() - response_instant + chrono::Duration::seconds(60);

        let sp = ServiceProvider {
            metadata_url: Some("http://test_accept_signed_with_correct_key.test".into()),
            acs_url: Some("http://sp.example.com/demo1/index.php?acs".into()),
            idp_metadata: idp_metadata_xml.parse().unwrap(),
            max_issue_delay,
            ..Default::default()
        };

        let authn_request = sp
            .make_authentication_request("http://dummy.fake/saml")
            .unwrap();

        let private_key = openssl::rsa::Rsa::private_key_from_der(private_key).unwrap();
        let private_key = openssl::pkey::PKey::from_rsa(private_key).unwrap();

        let signed_request_url = authn_request
            .signed_redirect("", private_key)
            .unwrap()
            .unwrap();

        // percent encoeded URL:
        //   http://dummy.fake/saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        // percent encoded URI:
        //   /saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        let uri_string: &String = &signed_request_url[url::Position::BeforePath..].to_string();
        assert!(uri_string.starts_with("/saml?SAMLRequest="));

        let url_verifier =
            UrlVerifier::from_x509(&sp.idp_signing_certs().unwrap().unwrap()[0]).unwrap();

        assert!(url_verifier
            .verify_percent_encoded_request_uri_string(uri_string)
            .unwrap(),);
    }

    #[test]
    fn test_verify_uri_ec() {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/ec_private.pem"
        ));

        let idp_metadata_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/idp_ecdsa_metadata.xml"
        ));

        let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
        let max_issue_delay = Utc::now() - response_instant + chrono::Duration::seconds(60);

        let sp = ServiceProvider {
            metadata_url: Some("http://test_accept_signed_with_correct_key.test".into()),
            acs_url: Some("http://sp.example.com/demo1/index.php?acs".into()),
            idp_metadata: idp_metadata_xml.parse().unwrap(),
            max_issue_delay,
            ..Default::default()
        };

        let authn_request = sp
            .make_authentication_request("http://dummy.fake/saml")
            .unwrap();

        let private_key = openssl::ec::EcKey::private_key_from_pem(private_key).unwrap();
        let private_key = openssl::pkey::PKey::from_ec_key(private_key).unwrap();

        let signed_request_url = authn_request
            .signed_redirect("", private_key)
            .unwrap()
            .unwrap();

        // percent encoeded URL:
        //   http://dummy.fake/saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        // percent encoded URI:
        //   /saml?SAMLRequest=..&SigAlg=..&Signature=..
        //
        let uri_string: &String = &signed_request_url[url::Position::BeforePath..].to_string();
        assert!(uri_string.starts_with("/saml?SAMLRequest="));

        let url_verifier =
            UrlVerifier::from_x509(&sp.idp_signing_certs().unwrap().unwrap()[0]).unwrap();

        assert!(url_verifier
            .verify_percent_encoded_request_uri_string(uri_string)
            .unwrap(),);
    }
}
