use base64::{engine::general_purpose, Engine as _};

// strip out 76-width format and decode base64
pub fn decode_x509_cert(x509_cert: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped = x509_cert
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| !b" \n\t\r\x0b\x0c".contains(b))
        .collect::<Vec<u8>>();

    general_purpose::STANDARD.decode(stripped)
}

// 76-width base64 encoding (MIME)
pub fn mime_encode_x509_cert(x509_cert_der: &[u8]) -> String {
    data_encoding::BASE64_MIME.encode(x509_cert_der)
}
