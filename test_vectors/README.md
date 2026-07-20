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

# Generating encrypted responses for tests

The `response_encrypted_aes{192,256}_{cbc,gcm}.xml` and `response_encrypted_valid_aes{192,256}_{cbc,gcm}.xml` fixtures are generated with `xmlsec1 --encrypt`, using the existing `sp_cert.pem` / `sp_private.pem` keypair (rsa-oaep-mgf1p key transport).

Step 1 — extract the plaintext assertion from the existing AES-128-CBC fixture (the `<xenc:EncryptedData>` element is self-contained namespace-wise, so it can be passed directly to `xmlsec1 --decrypt`):

```bash
# Extract the inner <xenc:EncryptedData> element to a standalone file.
python3 -c "
import re
with open('response_encrypted_valid.xml') as f:
    print(re.search(r'<xenc:EncryptedData.*?</xenc:EncryptedData>', f.read(), re.DOTALL).group(0))
" > /tmp/encrypted_data.xml

# Decrypt it to obtain the plaintext <saml:Assertion>.
xmlsec1 --decrypt --lax-key-search --privkey-pem sp_private.pem,sp_cert.pem /tmp/encrypted_data.xml \
    | tail -n +2 > /tmp/plaintext_assertion.xml
```

Step 2 — create an encryption template per algorithm. Example for AES-256-CBC (substitute `aes192-cbc` for the AES-192-CBC variant, or use the `xmlenc11` namespace and `aes{192,256}-gcm` for GCM):

```xml
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
    <dsig:KeyInfo>
        <xenc:EncryptedKey>
            <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
            <xenc:CipherData>
                <xenc:CipherValue/>
            </xenc:CipherData>
        </xenc:EncryptedKey>
    </dsig:KeyInfo>
    <xenc:CipherData>
        <xenc:CipherValue/>
    </xenc:CipherData>
</xenc:EncryptedData>
```

Step 3 — encrypt the plaintext with `xmlsec1 --encrypt`, generating a fresh AES session key wrapped with rsa-oaep-mgf1p:

```bash
xmlsec1 --encrypt --lax-key-search \
    --pubkey-cert-pem sp_cert.pem \
    --session-key aes-256 \
    --xml-data /tmp/plaintext_assertion.xml \
    --output /tmp/encrypted_data_aes256_cbc.xml \
    template_aes256_cbc.xml
```

Step 4 — wrap the resulting `<xenc:EncryptedData>` in a `<samlp:Response>` envelope (mirroring `response_encrypted.xml` / `response_encrypted_valid.xml`). When inlining the encrypted block, restore `xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"` on the `<dsig:KeyInfo>` element — `xmlsec1` strips the redundant namespace declaration since the prefix is already in scope from the parent, but samael's serde-based parser requires the explicit attribute on the element itself (see `EncryptedKeyInfo.ds` in `src/key_info.rs`).
