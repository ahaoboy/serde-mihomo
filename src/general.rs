//! General (top level, non networking specific) options.

use crate::macros::string_enum;
use crate::value::{Extra, Text};

string_enum! {
    /// How mihomo decides whether to look up the owning process of a connection.
    pub enum FindProcessMode {
        /// Always match every connection against the process table.
        Always => "always",
        /// Let mihomo decide (default).
        Strict => "strict",
        /// Never match processes; recommended on routers.
        Off => "off",
    }
}

string_enum! {
    /// The global routing mode.
    pub enum Mode {
        /// Evaluate the `rules` list.
        Rule => "rule",
        /// Route everything through the first proxy.
        Global => "global",
        /// Route everything directly.
        Direct => "direct",
    }
}

string_enum! {
    /// The verbosity of the mihomo log.
    pub enum LogLevel {
        /// Disable logging entirely.
        Silent => "silent",
        /// Log errors only.
        Error => "error",
        /// Log warnings and errors.
        Warning => "warning",
        /// Log informational messages and above.
        Info => "info",
        /// Log everything.
        Debug => "debug",
    }
}

string_enum! {
    /// The matching engine used by `GeoSite` rule sets.
    pub enum GeositeMatcher {
        /// The compact, default matcher.
        Succinct => "succinct",
        /// The V2Ray compatible matcher.
        Mph => "mph",
        /// Alias of [`GeositeMatcher::Mph`] used by Xray.
        Hybrid => "hybrid",
    }
}

/// A TCP/UDP port.
///
/// Most fields accept a plain integer, but inbound listeners also accept a
/// "ports" expression such as `200,204,401-429,501-503`.
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum Ports {
    /// A single port number.
    Number(u16),
    /// A port expression or a comma separated list of ports and ranges.
    Expression(String),
}

impl std::fmt::Display for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(port) => write!(f, "{port}"),
            Self::Expression(expression) => f.write_str(expression),
        }
    }
}

impl From<u16> for Ports {
    fn from(port: u16) -> Self {
        Self::Number(port)
    }
}

/// Download locations for the geodata files used by `GEOIP` and `GEOSITE`
/// rules.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct GeoxUrl {
    /// URL of `geoip.dat`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<Text>,
    /// URL of `geosite.dat`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite: Option<Text>,
    /// URL of `geoip.metadb`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mmdb: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// CORS policy of the RESTful external controller.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct ExternalControllerCors {
    /// Origins allowed to call the API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_origins: Vec<String>,
    /// Whether requests from private network addresses are allowed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_private_network: bool,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `profile` section: persistence of runtime state.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Profile {
    /// Persist the group/node selected in the UI.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_selected: bool,
    /// Persist the fake-ip cache between restarts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_fake_ip: bool,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `experimental` section.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Experimental {
    /// Disable `quic-go`'s GSO support (equivalent to
    /// `QUIC_GO_DISABLE_GSO=1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quic_go_disable_gso: Option<bool>,
    /// Rewrite IPv4 literals into `4in6` form before dialing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialer_ip4p_convert: Option<bool>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Ports and inbound authentication shared by every general option.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct General {
    /// HTTP(S) proxy port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Ports>,
    /// SOCKS5 proxy port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<Ports>,
    /// Mixed HTTP(S) and SOCKS proxy port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<Ports>,
    /// Transparent proxy port (Linux and macOS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redir_port: Option<Ports>,
    /// TProxy port (Linux).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tproxy_port: Option<Ports>,
    /// Allow connections from the local network.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_lan: bool,
    /// Address the inbound listeners bind to; only meaningful with
    /// `allow-lan`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<Text>,
    /// `username:password` pairs accepted by the inbound listeners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    /// Source IP ranges that bypass authentication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_auth_prefixes: Vec<String>,
    /// Destination IP ranges allowed to use the proxy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan_allowed_ips: Vec<String>,
    /// Destination IP ranges denied from using the proxy; takes precedence over
    /// `lan-allowed-ips`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan_disallowed_ips: Vec<String>,
    /// Process matching policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find_process_mode: Option<FindProcessMode>,
    /// Global routing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Log verbosity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
    /// Master switch for IPv6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
    /// Geodata download locations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geox_url: Option<GeoxUrl>,
    /// Automatically refresh geodata files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_auto_update: Option<bool>,
    /// Geodata refresh interval, in hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_update_interval: Option<u32>,
    /// Matcher implementation used by `GeoSite`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite_matcher: Option<GeositeMatcher>,
    /// Dial every candidate IP concurrently and keep the fastest handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_concurrent: Option<bool>,
    /// Delay TCP dialing to collect multiple candidate addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified_delay: Option<bool>,
    /// Outbound network interface to bind to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<Text>,
    /// `fwmark` applied to outbound sockets (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    /// Disable TCP keep-alive probes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_keep_alive: Option<bool>,
    /// Idle time before the first keep-alive probe, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_idle: Option<u32>,
    /// Interval between keep-alive probes, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_interval: Option<u32>,
    /// Address of the RESTful external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<Text>,
    /// HTTPS address of the RESTful external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_tls: Option<Text>,
    /// CORS policy of the external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_cors: Option<ExternalControllerCors>,
    /// Unix socket exposed by the external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_unix: Option<Text>,
    /// Windows named pipe exposed by the external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_pipe: Option<Text>,
    /// `fwmark` applied to the controller sockets (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller_routing_mark: Option<i32>,
    /// Directory of the static web UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<Text>,
    /// Name of the web UI directory to serve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui_name: Option<Text>,
    /// URL of a web UI archive to download and extract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui_url: Option<Text>,
    /// Path on the external controller that serves DoH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_doh_server: Option<Text>,
    /// Bearer secret required by the external controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Text>,
    /// Client fingerprint applied to every node that does not override it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_client_fingerprint: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

impl General {
    /// Returns the inbound ports that are enabled, in the order mihomo listens
    /// on them: `port`, `socks-port`, `mixed-port`, `redir-port`, `tproxy-port`.
    ///
    /// ```
    /// # use serde_mihomo::Config;
    /// let config = Config::from_yaml_str("mixed-port: 7890\nsocks-port: 7891\n")?;
    /// let ports: Vec<_> = config.general.enabled_ports().collect();
    /// assert_eq!(ports[0].0, "socks-port");
    /// # Ok::<(), serde_mihomo::Error>(())
    /// ```
    pub fn enabled_ports(&self) -> impl Iterator<Item = (&'static str, &Ports)> {
        [
            ("port", self.port.as_ref()),
            ("socks-port", self.socks_port.as_ref()),
            ("mixed-port", self.mixed_port.as_ref()),
            ("redir-port", self.redir_port.as_ref()),
            ("tproxy-port", self.tproxy_port.as_ref()),
        ]
        .into_iter()
        .filter_map(|(name, ports)| ports.map(|ports| (name, ports)))
    }
}
