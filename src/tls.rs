//! TLS material used by the external controller and by inbound listeners.

use crate::macros::string_enum;
use crate::value::{Extra, Text};

string_enum! {
    /// Mutual-TLS policy of an inbound listener.
    pub enum ClientAuthType {
        /// Client certificates are not requested (the empty string also means
        /// this, which mihomo treats as "disabled").
        Disabled => "",
        /// Request a client certificate but do not require one.
        Request => "request",
        /// Require a client certificate but accept any issuer.
        RequireAny => "require-any",
        /// Verify the client certificate when one is presented.
        VerifyIfGiven => "verify-if-given",
        /// Require and verify a client certificate.
        RequireAndVerify => "require-and-verify",
    }
}

/// The `tls` section, reused by `external-controller-tls` and by listeners that
/// expose TLS.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Tls {
    /// PEM encoded certificate, or the path to a certificate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Text>,
    /// PEM encoded private key, or the path to a private key file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Text>,
    /// Additional PEM encoded certificates to trust.
    ///
    /// mihomo spells this key `custom-certifactes`; the correctly spelled alias
    /// is accepted as well.
    #[serde(
        default,
        rename = "custom-certifactes",
        alias = "custom-certificates",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_certificates: Vec<String>,
    /// Mutual-TLS policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_type: Option<ClientAuthType>,
    /// PEM encoded client certificate authority, or the path to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_cert: Option<Text>,
    /// Encrypted Client Hello keys, generated with
    /// `mihomo generate ech-keypair <domain>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech_key: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
