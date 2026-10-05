//! The `listeners` section: additional inbound listeners.

use crate::general::Ports;
use crate::macros::string_enum;
use crate::tls::ClientAuthType;
use crate::tun::TunStack;
use crate::value::{Extra, OneOrMany, StringMap, Text};

string_enum! {
    /// The protocol served by an inbound listener.
    pub enum ListenerType {
        /// `SOCKS5` inbound.
        Socks => "socks",
        /// HTTP(S) inbound.
        Http => "http",
        /// Mixed HTTP(S) and `SOCKS5` inbound.
        Mixed => "mixed",
        /// Transparent proxy inbound (Linux, macOS).
        Redir => "redir",
        /// TProxy inbound (Linux).
        Tproxy => "tproxy",
        /// Shadowsocks inbound.
        Shadowsocks => "shadowsocks",
        /// Snell inbound.
        Snell => "snell",
        /// VMess inbound.
        Vmess => "vmess",
        /// VLESS inbound.
        Vless => "vless",
        /// Trojan inbound.
        Trojan => "trojan",
        /// TUIC inbound.
        Tuic => "tuic",
        /// ShadowQUIC inbound.
        Shadowquic => "shadowquic",
        /// AnyTLS inbound.
        Anytls => "anytls",
        /// Mieru inbound.
        Mieru => "mieru",
        /// Sudoku inbound.
        Sudoku => "sudoku",
        /// Hysteria2 inbound.
        Hysteria2 => "hysteria2",
        /// Hysteria2 port hopping / realm inbound.
        Hysteria2Realm => "hysteria2-realm",
        /// TrustTunnel inbound.
        Trusttunnel => "trusttunnel",
        /// A simple port forwarder.
        Tunnel => "tunnel",
        /// A TUN device managed by the listener itself.
        Tun => "tun",
    }
}

/// The `jls-upstream` of a ShadowQUIC listener.
///
/// Connections that fail JLS authentication are forwarded to this QUIC
/// endpoint, which therefore looks like a regular QUIC server.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct JlsUpstream {
    /// Address of the masqueraded QUIC upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<Text>,
    /// SNI used towards the upstream; derived from `addr` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<Text>,
    /// Proxy used to reach the upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Text>,
    /// Forwarding rate limit in bits per second; `0` means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u64>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// An account accepted by an inbound listener.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct ListenerUser {
    /// User name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<Text>,
    /// Password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `users` of an inbound listener.
///
/// ```yaml
/// users:                                 # list form
///   - username: aaa
///     password: aaa
/// users:                                 # map form
///   aaa: aaa
/// ```
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum ListenerUsers {
    /// A list of accounts.
    List(Vec<ListenerUser>),
    /// A `username: password` mapping.
    Map(StringMap<OneOrMany<String>>),
}

impl ListenerUsers {
    /// Returns the number of accounts.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::List(users) => users.len(),
            Self::Map(users) => users.len(),
        }
    }

    /// Returns `true` when no account is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An entry of the `listeners` list.
#[derive(..SerdeEq)]
#[serde(rename_all = "kebab-case")]
pub struct Listener {
    /// Unique name of the listener.
    pub name: String,
    /// Protocol served by the listener.
    #[serde(rename = "type")]
    pub listener_type: ListenerType,
    /// Port(s) the listener binds to; also accepts expressions such as
    /// `200,204,401-429`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Ports>,
    /// Address the listener binds to; defaults to `0.0.0.0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<Text>,
    /// `fwmark` applied to the listener socket (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    /// Sub-rule used instead of the global `rules`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<Text>,
    /// Hand the inbound traffic directly to this proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Text>,
    /// Whether UDP is forwarded; defaults to `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    /// Accounts accepted by this listener; overrides `authentication`.
    ///
    /// mihomo accepts both a list of `{username, password}` mappings and a
    /// `username: password` mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<ListenerUsers>,

    // --- TLS -----------------------------------------------------------
    /// PEM encoded certificate, or the path to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Text>,
    /// PEM encoded private key, or the path to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Text>,
    /// Mutual-TLS policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_type: Option<ClientAuthType>,
    /// PEM encoded client certificate authority, or the path to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_cert: Option<Text>,
    /// Encrypted Client Hello keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech_key: Option<Text>,
    /// REALITY configuration (`vless` listeners).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_config: Option<Extra>,
    /// JLS upstream used by ShadowQUIC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jls_upstream: Option<JlsUpstream>,
    /// Congestion controller of a TrustTunnel listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_controller: Option<Text>,

    // --- credentials ---------------------------------------------------
    /// Cipher of a Shadowsocks listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<Text>,
    /// Password of a Shadowsocks listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Text>,
    /// Pre-shared key of a Snell listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<Text>,
    /// Snell protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Key of a ShadowQUIC or Sudoku listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Text>,

    // --- tunnel / tun ---------------------------------------------------
    /// Network protocols forwarded by a `tunnel` listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<OneOrMany<String>>,
    /// Target of a `tunnel` listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Text>,
    /// Addresses hijacked by a `tun` listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_hijack: Vec<String>,
    /// IPv4 address of a `tun` listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet4_address: Option<Text>,
    /// IPv6 address of a `tun` listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet6_address: Option<Text>,
    /// Network stack of a `tun` listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<TunStack>,

    // --- protocol specific scalars --------------------------------------
    /// Mieru transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Text>,
    /// Sudoku AEAD method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aead_method: Option<Text>,
    /// Sudoku table type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_type: Option<Text>,
    /// Sudoku padding bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding_min: Option<u32>,
    /// Sudoku padding bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding_max: Option<u32>,
    /// Sudoku handshake timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_timeout: Option<u64>,
    /// Sudoku HTTP mask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub httpmask: Option<serde_json::Value>,
    /// Sudoku: enable a pure downlink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_pure_downlink: Option<bool>,
    /// Token of a hysteria2-realm listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<Text>,
    /// Realm name pattern of a hysteria2-realm listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_name_pattern: Option<Text>,
    /// Maximum number of realms of a hysteria2-realm listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_realms: Option<u32>,
    /// Maximum number of realms per IP of a hysteria2-realm listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_realms_per_ip: Option<u32>,
    /// Header used to read the real client address of a hysteria2-realm
    /// listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_proxy_header: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
