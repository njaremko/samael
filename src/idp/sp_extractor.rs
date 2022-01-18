use super::error::Error;
use crate::crypto;
use crate::metadata::EntityDescriptor;

pub struct SPMetadataExtractor(EntityDescriptor);

pub struct RequiredAttribute {
    pub name: String,
    pub format: Option<String>,
}

pub struct Acs {
    pub bind_type: BindType,
    pub url: String,
}

pub enum BindType {
    Post,
}

impl SPMetadataExtractor {
    pub fn try_from_xml(xml: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(xml.parse()?))
    }

    pub fn issuer(&self) -> Result<String, Error> {
        self.0.entity_id.clone().ok_or(Error::MissingAudience)
    }

    pub fn acs(&self) -> Result<Acs, Error> {
        let (binding, location) = self
            .0
            .sp_sso_descriptors
            .as_ref()
            .and_then(|d| d.first())
            .and_then(|sd| sd.assertion_consumer_services.first())
            .map(|acs| (acs.binding.as_str(), acs.location.as_str()))
            .ok_or(Error::MissingAcsUrl)?;

        if binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
            return Err(Error::NonHttpPostBindingUnsupported);
        }

        Ok(Acs {
            bind_type: BindType::Post,
            url: location.to_string(),
        })
    }

    pub fn required_attributes(&self) -> Vec<RequiredAttribute> {
        self.0
            .sp_sso_descriptors
            .as_ref()
            .and_then(|d| d.first())
            .and_then(|sd| sd.attribute_consuming_services.as_ref())
            .and_then(|s| s.first())
            .map(|acs| {
                acs.request_attributes
                    .iter()
                    .filter(|ra| ra.is_required == Some(true))
                    .map(|ra| RequiredAttribute {
                        name: ra.name.clone(),
                        format: ra.name_format.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn verification_cert(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let sp_descriptors = self
            .0
            .sp_sso_descriptors
            .as_ref()
            .ok_or(Error::NoSPSsoDescriptors)?;

        for sp_descriptor in sp_descriptors {
            match sp_descriptor.key_descriptors.as_ref() {
                Some(kd) => {
                    // grab the first signing key
                    let data = kd
                        .iter()
                        .filter(|d| d.is_signing())
                        .flat_map(|d| {
                            d.key_info
                                .x509_data
                                .iter()
                                .flat_map(|d| d.certificates.iter())
                        })
                        .next()
                        .ok_or(Error::NoCertificate)?;

                    return Ok(crypto::decode_x509_cert(data.as_str())?);
                }
                None => continue,
            };
        }

        Err(Error::NoCertificate.into())
    }
}
