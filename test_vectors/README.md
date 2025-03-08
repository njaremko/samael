`idp_cert.der` corresponds to `idp_metadata.xml`:

    $ grep "$(openssl x509 -inform der -in idp_cert.der | grep -v -- '-----' | tr -d '\n')" *
    idp_metadata.xml:                    <ds:X509Certificate>....

TODO it is unknown what has signed `response_signed.xml`, it's not the certificate in `idp_metadata.xml`, see `idp::tests::test_accept_signed_with_correct_key_idp`

`response_encrypted.xml` is an encrypted response, it is encrypted with the private key in `sp_private.pem`. `sp_private.pem` is the private key of `sp_cert.pem`.

# Generating signed responses for tests

`public.der` and `private.der` correspond to `idp_2_metadata.xml`, and are used to sign `response_signed_by_idp_2.xml`. Update `response_signed_template.xml` and then generate `response_signed_by_idp_2.xml` using:

```bash
xmlsec1 --sign --privkey-der private.der,public.der --output response_signed_by_idp_2.xml --id-attr:ID Response response_signed_template.xml
```

Validate with:

```bash
xmlsec1 --verify --trusted-der public.der --id-attr:ID Response response_signed_by_idp_2.xml
```

Both `response_signed_by_idp_2.xml` and `authn_request_sign_template.xml` are used in unit tests, where `authn_request_sign_template.xml` is signed in the test.

To generate `response_signed_by_idp_ecdsa.xml`:

```bash
xmlsec1 --sign --privkey-der ec_private.der,ec_cert.der --output response_signed_by_idp_ecdsa.xml --id-attr:ID Response response_signed__ecdsa-template.xml
```

How the EC stuff was generated:

```bash
# Step 1: Generate ECDSA Private Key
openssl ecparam -genkey -name prime256v1 -out ec_private.pem

# Step 2: Create a Certificate Signing Request (CSR)
openssl req -new -key ec_private.pem -out ec_csr.pem

# Step 3: Self-Sign the CSR to Create an X.509 Certificate
openssl x509 -req -in ec_csr.pem -signkey ec_private.pem -out ec_cert.pem -days 365000

# Step 4: Convert the Private Key and Certificate to DER Format
openssl pkcs8 -topk8 -inform PEM -outform DER -in ec_private.pem -out ec_private.der -nocrypt
openssl x509 -in ec_cert.pem -outform DER -out ec_cert.der

# Step 5: Use the Private Key and Certificate with xmlsec1
xmlsec1 --sign --privkey-der ec_private.der,ec_cert.der --output response_signed_by_idp_ecdsa.xml --id-attr:ID Response response_signed_template.xml
```
