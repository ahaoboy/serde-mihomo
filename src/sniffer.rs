//! The `sniffer` section.

use crate::general::Ports;
use crate::value::Extra;

/// Per-protocol sniffer configuration.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct SniffProtocol {
    /// Ports that are sniffed; defaults to the protocol's well known port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<Ports>,
    /// Override the global `sniffer.override-destination` for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_destination: Option<bool>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `sniffer.sniff` map.
///
/// Every entry is optional; omitting one (or writing it as `null`) disables
/// sniffing for that protocol.
#[derive(..SerdeEqDefault)]
pub struct Sniff {
    /// TLS ClientHello sniffing.
    #[serde(rename = "TLS", alias = "tls", skip_serializing_if = "Option::is_none")]
    pub tls: Option<SniffProtocol>,
    /// HTTP request sniffing.
    #[serde(
        rename = "HTTP",
        alias = "http",
        skip_serializing_if = "Option::is_none"
    )]
    pub http: Option<SniffProtocol>,
    /// QUIC Initial packet sniffing.
    #[serde(
        rename = "QUIC",
        alias = "quic",
        skip_serializing_if = "Option::is_none"
    )]
    pub quic: Option<SniffProtocol>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `sniffer` section.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Sniffer {
    /// Enable domain sniffing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable: bool,
    /// Force sniffing for traffic that uses `redir-host` style DNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_dns_mapping: Option<bool>,
    /// Force sniffing even for connections that already carry a domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_pure_ip: Option<bool>,
    /// Use the sniffed domain as the actual destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_destination: Option<bool>,
    /// Per-protocol configuration; not yet enabled (it overrides `sniffing` and
    /// `port-whitelist`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniff: Option<Sniff>,
    /// Domains that are always sniffed, regardless of source address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub force_domain: Vec<String>,
    /// Domains that are never sniffed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_domain: Vec<String>,
    /// Source IP ranges that are skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_src_address: Vec<String>,
    /// Destination IP ranges that are skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_dst_address: Vec<String>,
    /// Deprecated list of sniffed protocols; ignored when [`Sniffer::sniff`] is
    /// configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sniffing: Vec<String>,
    /// Deprecated list of sniffed ports; ignored when [`Sniffer::sniff`] is
    /// configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_whitelist: Vec<String>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
