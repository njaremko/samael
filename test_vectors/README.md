`idp_cert.der` corresponds to `idp_metadata.xml`:

    $ grep "$(openssl x509 -inform der -in idp_cert.der | grep -v -- '-----' | tr -d '\n')" *
    idp_metadata.xml:                    <ds:X509Certificate>....
    
TODO it is unknown what has signed `response_signed.xml`, it's not the certificate in `idp_metadata.xml`, see `idp::tests::test_accept_signed_with_correct_key_idp`

`public.der` and `private.der` correspond to `idp_2_metadata.xml`, and are used to sign `response_signed_by_idp_2.xml`. Generate `response_signed_by_idp_2.xml` using:

    xmlsec1 --sign --privkey-der private.der,public.der --output response_signed_by_idp_2.xml --id-attr:ID Response response_signed_template.xml

Validate with:

    xmlsec1 --verify --trusted-der public.der --id-attr:ID Response response_signed_by_idp_2.xml

Both `response_signed_by_idp_2.xml` and `authn_request_sign_template.xml` are used in unit tests, where `authn_request_sign_template.xml` is signed in the test.

