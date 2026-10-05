//! Proxies, proxy groups and proxy providers.
//!
//! mihomo ships dozens of proxy protocols that each add their own keys. This
//! module models the fields shared by (nearly) every protocol and keeps the rest
//! in [`Proxy::extra`], so new protocols and new keys keep working while the
//! common fields stay typed.

use crate::general::Ports;
use crate::macros::string_enum;
use crate::value::{Extra, OneOrMany, StringMap, Text};

string_enum! {
    /// The protocol implemented by a proxy.
    ///
    /// The list covers the documented mihomo protocols; anything else is kept in
    /// [`ProxyType::Other`] so newer releases keep working.
    pub enum ProxyType {
        /// HTTP(S) proxy.
        Http => "http",
        /// `SOCKS5` proxy.
        Socks5 => "socks5",
        /// `SOCKS5` proxy (legacy spelling).
        Socks => "socks",
        /// Shadowsocks.
        Ss => "ss",
        /// ShadowsocksR.
        Ssr => "ssr",
        /// VMess.
        Vmess => "vmess",
        /// VLESS.
        Vless => "vless",
        /// Trojan.
        Trojan => "trojan",
        /// Hysteria v1.
        Hysteria => "hysteria",
        /// Hysteria v2.
        Hysteria2 => "hysteria2",
        /// TUIC.
        Tuic => "tuic",
        /// WireGuard.
        Wireguard => "wireguard",
        /// Snell.
        Snell => "snell",
        /// SSH tunnel.
        Ssh => "ssh",
        /// Mieru.
        Mieru => "mieru",
        /// AnyTLS.
        Anytls => "anytls",
        /// ShadowQUIC.
        Shadowquic => "shadowquic",
        /// Sudoku.
        Sudoku => "sudoku",
        /// Gost relay.
        GostRelay => "gost-relay",
        /// MASQUE.
        Masque => "masque",
        /// OpenVPN.
        Openvpn => "openvpn",
        /// Tailscale.
        Tailscale => "tailscale",
        /// ZeroTier.
        Zerotier => "zerotier",
        /// EasyTier.
        Easytier => "easytier",
        /// TrustTunnel.
        Trusttunnel => "trusttunnel",
        /// Rematch: re-evaluate an earlier rule.
        Rematch => "rematch",
        /// Direct connection.
        Direct => "direct",
        /// Built-in DNS outbound.
        Dns => "dns",
    }
}

/// A nested, protocol specific option object (`ws-opts`, `grpc-opts`, ...).
///
/// Their layouts differ per protocol and change often, so they are kept as free
/// form mappings and round-trip unchanged.
pub type ProxyOptions = Extra;

/// WireGuard "reserved" bytes.
///
/// mihomo accepts both the three byte values and their base64 representation.
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum Reserved {
    /// Three raw byte values, for example `[209, 98, 59]`.
    Bytes(Vec<u8>),
    /// The base64 encoded form, for example `"U4An"`.
    Base64(String),
}

/// A health check declaration.
///
/// Nodes accept the shorthand `health-check: true` (or `false`), while providers
/// use the full mapping.
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum HealthCheckConfig {
    /// Enable or disable the default health check.
    Enabled(bool),
    /// Full health check configuration.
    Detailed(HealthCheck),
}

/// A proxy node.
#[derive(..SerdeEq)]
#[serde(rename_all = "kebab-case")]
pub struct Proxy {
    /// Unique name of the node.
    pub name: String,
    /// Protocol implemented by the node.
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,

    /// Server host name or IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Text>,
    /// Server port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Ports>,
    /// Encrypt UDP traffic through this node; defaults to `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,

    // --- credentials ---------------------------------------------------
    /// Password (`ss`, `ssr`, `trojan`, `snell`, `hysteria2`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Text>,
    /// User name (`http`, `socks5`, `ssh`, `mieru`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<Text>,
    /// UUID (`vmess`, `vless`, `tuic`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Text>,
    /// Pre-shared key (`snell`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<Text>,
    /// Authentication string (`hysteria`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_str: Option<Text>,

    // --- cryptography --------------------------------------------------
    /// Cipher / encryption method (`ss`, `ssr`, `vmess`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<Text>,
    /// Obfuscation method (`ssr`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Text>,
    /// Obfuscation options (`ssr`, `snell`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs_opts: Option<ProxyOptions>,
    /// Transport protocol (`ssr`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Text>,
    /// Parameters of the protocol above (`ssr`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_param: Option<Text>,
    /// VLESS encryption method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Text>,

    // --- TLS -----------------------------------------------------------
    /// Enable TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    /// TLS server name indication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<Text>,
    /// TLS server name (alias of `sni` used by some protocols).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servername: Option<Text>,
    /// ALPN protocols to negotiate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<OneOrMany<String>>,
    /// Certificate fingerprint used by uTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Text>,
    /// uTLS client fingerprint preset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<Text>,
    /// Do not verify the server certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    /// Custom certificate authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<Text>,
    /// Custom certificate authority, inline PEM (`ca-str`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_str: Option<Text>,
    /// REALITY options (`vless`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_opts: Option<ProxyOptions>,

    // --- transport -----------------------------------------------------
    /// Transport network (`tcp`, `ws`, `grpc`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Text>,
    /// WebSocket options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<ProxyOptions>,
    /// gRPC options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<ProxyOptions>,
    /// HTTP/2 options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<ProxyOptions>,
    /// mKCP options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mkcp_opts: Option<ProxyOptions>,
    /// XHTTP options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_opts: Option<ProxyOptions>,
    /// Mieru transport options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Text>,
    /// MASQUE / Tailscale / ZeroTier network name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_name: Option<Text>,
    /// EasyTier network secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_secret: Option<Text>,
    /// EasyTier peers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<String>>,

    // --- protocol specific scalars -------------------------------------
    /// VMess alter id.
    #[serde(
        rename = "alterId",
        alias = "alter-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub alter_id: Option<u32>,
    /// Snell / shadowquic version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Shadowsocks plugin name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<Text>,
    /// Shadowsocks plugin options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<ProxyOptions>,
    /// VLESS flow control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<Text>,
    /// Trojan flow show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_show: Option<bool>,
    /// Hysteria bandwidth up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<Text>,
    /// Hysteria bandwidth down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<Text>,
    /// TUIC token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<Text>,
    /// TUIC: do not send SNI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sni: Option<bool>,
    /// TUIC: reduce round trips on handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_rtt: Option<bool>,
    /// TUIC request timeout, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<u64>,
    /// TUIC UDP relay mode (`native`, `quic`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<Text>,

    // --- addresses (wireguard, masque, tun-like) ------------------------
    /// Local IPv4 address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Text>,
    /// Local IPv6 address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Text>,
    /// WireGuard private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Text>,
    /// WireGuard peer public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Text>,
    /// WireGuard reserved bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Reserved>,
    /// Interface MTU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    // --- OpenVPN --------------------------------------------------------
    /// OpenVPN layer 4 protocol (`tcp`, `udp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<Text>,
    /// OpenVPN / listener certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Text>,
    /// OpenVPN client certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<Text>,
    /// OpenVPN client key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Text>,

    // --- dialer ---------------------------------------------------------
    /// Proxy used to reach this node's server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<Text>,
    /// Interface this node binds to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<Text>,
    /// `fwmark` applied to sockets of this node (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    /// Enable TCP fast open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfo: Option<bool>,
    /// Enable multipath TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mptcp: Option<bool>,
    /// Connection multiplexing options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smux: Option<ProxyOptions>,

    // --- rematch --------------------------------------------------------
    /// Proxy name substituted by a `rematch` rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_rematch_name: Option<Text>,
    /// Sub-rule re-evaluated by a `rematch` rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_sub_rule: Option<Text>,

    /// Per-node health check override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
    /// Protocol specific keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

string_enum! {
    /// The algorithm used by a [`ProxyGroup`].
    ///
    /// Unknown values are preserved through `Other` so that groups added by a
    /// newer mihomo release keep working.
    pub enum ProxyGroupType {
        /// The user picks a node manually.
        Select => "select",
        /// The node with the lowest latency wins.
        UrlTest => "url-test",
        /// The first healthy node in declaration order wins.
        Fallback => "fallback",
        /// Nodes are picked by a load balancing strategy.
        LoadBalance => "load-balance",
        /// Nodes are chained into a relay.
        Relay => "relay",
    }
}

string_enum! {
    /// The strategy used by a `load-balance` group.
    pub enum LoadBalanceStrategy {
        /// Sticky sessions: requests from the same source keep the same node
        /// for ten minutes.
        StickySessions => "sticky-sessions",
        /// Consistent hashing: the same key keeps the same node.
        ConsistentHashing => "consistent-hashing",
        /// Requests are distributed round-robin.
        RoundRobin => "round-robin",
    }
}

/// A proxy group.
#[derive(..SerdeEq)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroup {
    /// Unique name of the group.
    pub name: String,
    /// Group algorithm.
    #[serde(rename = "type")]
    pub group_type: ProxyGroupType,
    /// Explicitly listed member nodes and groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<String>,
    /// Providers whose nodes are pulled into this group.
    #[serde(default, rename = "use", skip_serializing_if = "Vec::is_empty")]
    pub use_providers: Vec<String>,
    /// Regular expression used to filter provider nodes by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Text>,
    /// Regular expression used to exclude provider nodes by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<Text>,
    /// Node types that are excluded from providers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_type: Option<Text>,
    /// Include every proxy declared in the configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_all: Option<bool>,
    /// Include every proxy defined by a provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_all_proxies: Option<bool>,
    /// Include every provider as a whole.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_all_providers: Option<bool>,

    /// Health check URL (`url-test`, `fallback`, `load-balance`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Text>,
    /// Health check interval, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Latency tolerance, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<u64>,
    /// Only run health checks when the group is in use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    /// HTTP status considered healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
    /// Disable UDP for the whole group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_udp: Option<bool>,
    /// Load balancing strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<LoadBalanceStrategy>,
    /// Key used by the consistent-hashing strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_key: Option<Text>,
    /// Node selected by default in a `select` group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_selected: Option<Text>,
    /// Fallback used when the group ends up empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_fallback: Option<Text>,
    /// Icon shown for the group in the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Text>,
    /// Hide the group from the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A health check configuration.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct HealthCheck {
    /// Enable periodic health checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    /// URL that is fetched during a health check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Text>,
    /// Interval between checks, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Only check when the provider is actually used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    /// HTTP status considered healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
    /// Per-request timeout, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A `proxy-name` rewrite rule used by [`ProviderOverride`].
#[derive(..SerdeEq)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyNameRewrite {
    /// Regular expression matched against the node name.
    pub pattern: String,
    /// Replacement, which may reference capture groups with `$1`, `$2`, ...
    pub target: String,
}

/// The `override` section of a proxy provider.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct ProviderOverride {
    /// Override `skip-cert-verify` of every node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    /// Domain name used when verifying node certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_cert_verify: Option<Text>,
    /// Override the `udp` capability of every node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    /// Override the download bandwidth of every node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<Text>,
    /// Override the upload bandwidth of every node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<Text>,
    /// Route every node through this proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<Text>,
    /// Bind every node to this interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<Text>,
    /// `fwmark` applied to every node (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    /// IP version preference (`ipv4`, `ipv6`, `ipv4-prefer`, `ipv6-prefer`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<Text>,
    /// Prefix prepended to every node name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_prefix: Option<Text>,
    /// Suffix appended to every node name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_suffix: Option<Text>,
    /// Regular expression based node name rewrites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_name: Vec<ProxyNameRewrite>,
    /// `yq` style expressions applied after the fixed overrides above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_expr: Vec<String>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

string_enum! {
    /// How a proxy provider obtains its node list.
    pub enum ProxyProviderType {
        /// Download the node list from `url`.
        Http => "http",
        /// Read the node list from a local file.
        File => "file",
        /// The node list is declared inline in `payload`.
        Inline => "inline",
    }
}

/// Header values support both a scalar and a sequence of scalars.
pub type HeaderMap = StringMap<OneOrMany<String>>;

/// An entry of the `proxy-providers` map.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyProvider {
    /// How the provider obtains its nodes.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<ProxyProviderType>,
    /// Remote URL of the node list (`http` providers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Text>,
    /// Local path of the node list (`http` and `file` providers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Text>,
    /// Refresh interval, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Proxy used to download the node list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Text>,
    /// Maximum size of the downloaded file, in kilobytes; `0` means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
    /// Age secret key used to decrypt `age` encrypted node lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secret_key: Option<Text>,
    /// Extra HTTP headers used when downloading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<HeaderMap>,
    /// Health check applied to every node of the provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
    /// Fixed values applied to every downloaded node.
    #[serde(rename = "override", skip_serializing_if = "Option::is_none")]
    pub override_config: Option<ProviderOverride>,
    /// Proxy used to reach the nodes of this provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<Text>,
    /// Regular expression used to exclude nodes by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<Text>,
    /// Node types that are excluded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_type: Option<Text>,
    /// Inline node list (`inline` providers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<Proxy>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
