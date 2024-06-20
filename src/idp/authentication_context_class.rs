use std::{convert::TryFrom, fmt::Display};
/// The number of permutations of different characteristics ensures that there is a theoretically infinite number
/// of unique authentication contexts. The implication is that, in theory, any particular relying party would be
/// expected to be able to parse arbitrary authentication context declarations and, more importantly, to
/// analyze the declaration in order to assess the “quality” of the associated authentication assertion. Making
/// such an assessment is non-trivial.
///
/// Fortunately, an optimization is possible. In practice many authentication contexts will fall into categories
/// determined by industry practices and technology. For instance, many B2C web browser authentication
/// contexts will be (partially) defined by the principal authenticating to the authentication authority through the
/// presentation of a password over an SSL protected session. In the enterprise world, certificate-based
/// authentication will be common. Of course, the full authentication context is not limited to the specifics of
/// how the principal authenticated. Nevertheless, the authentication method is often the most visible
/// characteristic and as such, can serve as a useful classifer for a class of related authentication contexts.
///
/// The concept is expressed in this specification as a definition of a series of authentication context classes.
/// Each class defines a proper subset of the full set of authentication contexts. Classes have been chosen
/// as representative of the current practices and technologies for authentication technologies, and provide
/// asserting and relying parties a convenient shorthand when referring to authentication context issues.
///
/// For instance, an authentication authority may include with the complete authentication context declaration
/// it provides to a relying party an assertion that the authentication context also belongs to an authentication
/// context class. For some relying parties, this assertion is sufficient detail for it to be able to assign an
/// appropriate level of confidence to the associated authentication assertion. Other relying parties might
/// prefer to examine the complete authentication context declaration itself. Likewise, the ability to refer to an
/// authentication context class rather than being required to list the complete details of a specific
/// authentication context declaration will simplify how the relying party can express its desires and/or
/// requirements to an authentication authority.
///
/// Source:
/// Section 3, https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationContextClass {
    /// The Internet Protocol class is applicable when a principal is authenticated through the use of a provided IP
    /// address.
    InternetProtocol,
    /// The Internet Protocol Password class is applicable when a principal is authenticated through the use of a
    /// provided IP address, in addition to a username/password.
    InternetProtocolPassword,
    /// This class is applicable when the principal has authenticated using a password to a local authentication
    /// authority, in order to acquire a Kerberos ticket. That Kerberos ticket is then used for subsequent network
    /// authentication.
    Kerberos,
    /// Reflects no mobile customer registration procedures and an authentication of the mobile device without
    /// requiring explicit end-user interaction. This context class authenticates only the device and never the user;
    /// it is useful when services other than the mobile operator want to add a secure device authentication to
    /// their authentication process.
    MobileOneFactorUnregistered,
    /// Reflects no mobile customer registration procedures and a two-factor based authentication, such as
    /// secure device and user PIN. This context class is useful when a service other than the mobile operator
    /// wants to link their customer ID to a mobile supplied two-factor authentication service by capturing mobile
    /// phone data at enrollment.
    MobileTwoFactorUnregistered,
    /// Reflects mobile contract customer registration procedures and a single factor authentication. For example,
    /// a digital signing device with tamper resistant memory for key storage, such as the mobile MSISDN, but no
    /// required PIN or biometric for real-time user authentication.
    MobileOneFactorContract,
    /// Reflects mobile contract customer registration procedures and a two-factor based authentication. For
    /// example, a digital signing device with tamper resistant memory for key storage, such as a GSM SIM, that
    /// requires explicit proof of user identity and intent, such as a PIN or biometric.
    MobileTwoFactorContract,
    /// The Password class is applicable when a principal authenticates to an authentication authority through the
    /// presentation of a password over an unprotected HTTP session.
    Password,
    /// The PasswordProtectedTransport class is applicable when a principal authenticates to an authentication
    /// authority through the presentation of a password over a protected session
    PasswordProtectedTransport,
    /// The PreviousSession class is applicable when a principal had authenticated to an authentication authority
    /// at some point in the past using any authentication context supported by that authentication authority.
    /// Consequently, a subsequent authentication event that the authentication authority will assert to the relying
    /// party may be significantly separated in time from the principal's current resource access request.
    ///
    /// The context for the previously authenticated session is explicitly not included in this context class because
    /// the user has not authenticated during this session, and so the mechanism that the user employed to
    /// authenticate in a previous session should not be used as part of a decision on whether to now allow
    /// access to a resource.
    PreviousSession,
    /// The X509 context class indicates that the principal authenticated by means of a digital signature where the
    /// key was validated as part of an X.509 Public Key Infrastructure.
    PublicKeyX509,
    /// The PGP context class indicates that the principal authenticated by means of a digital signature where the
    /// key was validated as part of a PGP Public Key Infrastructure.
    PublicKeyPgp,
    /// The SPKI context class indicates that the principal authenticated by means of a digital signature where the
    /// key was validated via an SPKI Infrastructure.
    PublicKeySpki,
    /// This context class indicates that the principal authenticated by means of a digital signature according to
    /// the processing rules specified in the XML Digital Signature specification [XMLSig].
    XmlDigitalSignature,
    /// The Smartcard class is identified when a principal authenticates to an authentication authority using a
    /// smartcard.
    Smartcard,
    /// The SmartcardPKI class is applicable when a principal authenticates to an authentication authority through
    /// a two-factor authentication mechanism using a smartcard with enclosed private key and a PIN.
    SmartcardPki,
    /// The Software-PKI class is applicable when a principal uses an X.509 certificate stored in software to
    /// authenticate to the authentication authority.
    SoftwarePki,
    /// This class is used to indicate that the principal authenticated via the provision of a fixed-line telephone
    /// number, transported via a telephony protocol such as ADSL.
    Telephony,
    /// Indicates that the principal is "roaming" (perhaps using a phone card) and authenticates via the means of
    /// the line number, a user suffix, and a password element.
    NomadTelephony,
    /// This class is used to indicate that the principal authenticated via the provision of a fixed-line telephone
    /// number and a user suffix, transported via a telephony protocol such as ADSL.
    PersonalTelephony,
    /// Indicates that the principal authenticated via the means of the line number, a user suffix, and a password
    /// element.
    AuthenticatedTelephony,
    /// The Secure Remote Password class is applicable when the authentication was performed by means of
    /// Secure Remote Password as specified in [RFC 2945].
    SecureRemotePassword,
    /// This class indicates that the principal authenticated by means of a client certificate, secured with the
    /// SSL/TLS transport.
    TlsClient,
    /// The TimeSyncToken class is applicable when a principal authenticates through a time synchronization
    /// token.
    TimeSyncToken,
    /// The Unspecified class indicates that the authentication was performed by unspecified means.
    Unspecified,
}
impl AuthenticationContextClass {
    pub fn uri(&self) -> &'static str {
        match self {
            AuthenticationContextClass::InternetProtocol => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
            }
            AuthenticationContextClass::InternetProtocolPassword => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
            }
            AuthenticationContextClass::Kerberos => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
            }
            AuthenticationContextClass::MobileOneFactorUnregistered => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
            }
            AuthenticationContextClass::MobileTwoFactorUnregistered => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
            }
            AuthenticationContextClass::MobileOneFactorContract => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
            }
            AuthenticationContextClass::MobileTwoFactorContract => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
            }
            AuthenticationContextClass::Password => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
            }
            AuthenticationContextClass::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            AuthenticationContextClass::PreviousSession => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
            }
            AuthenticationContextClass::PublicKeyX509 => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
            }
            AuthenticationContextClass::PublicKeyPgp => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
            }
            AuthenticationContextClass::PublicKeySpki => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
            }
            AuthenticationContextClass::XmlDigitalSignature => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"
            }
            AuthenticationContextClass::Smartcard => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
            }
            AuthenticationContextClass::SmartcardPki => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
            }
            AuthenticationContextClass::SoftwarePki => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
            }
            AuthenticationContextClass::Telephony => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
            }
            AuthenticationContextClass::NomadTelephony => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
            }
            AuthenticationContextClass::PersonalTelephony => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"
            }
            AuthenticationContextClass::AuthenticatedTelephony => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
            }
            AuthenticationContextClass::SecureRemotePassword => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
            }
            AuthenticationContextClass::TlsClient => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
            }
            AuthenticationContextClass::TimeSyncToken => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
            }
            AuthenticationContextClass::Unspecified => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
            }
        }
    }
}
impl Display for AuthenticationContextClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.uri())
    }
}
impl Default for AuthenticationContextClass {
    fn default() -> Self {
        Self::Unspecified
    }
}
