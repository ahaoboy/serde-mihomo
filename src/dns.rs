//! The `dns` section.

use crate::macros::string_enum;
use crate::value::{Extra, OneOrMany, StringMap, Text};

string_enum! {
    /// The DNS cache eviction algorithm.
    pub enum CacheAlgorithm {
        /// Adaptive Replacement Cache, used by default.
        Arc => "arc",
        /// Least Recently Used.
        Lru => "lru",
    }
}

string_enum! {
    /// How mihomo answers A/AAAA queries.
    pub enum EnhancedMode {
        /// Return a synthetic address from the fake-ip pool and resolve the real
        /// address on demand.
        FakeIp => "fake-ip",
        /// Resolve names through the configured upstreams.
        RedirHost => "redir-host",
    }
}

string_enum! {
    /// How [`Dns::fake_ip_filter`] is interpreted.
    pub enum FakeIpFilterMode {
        /// Names matching the filter are *not* assigned a fake-ip (default).
        Blacklist => "blacklist",
        /// Only names matching the filter are assigned a fake-ip.
        Whitelist => "whitelist",
        /// Entries are full routing rules evaluated top to bottom.
        Rule => "rule",
    }
}

/// Condition under which the `fallback` nameservers are consulted.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct FallbackFilter {
    /// Consult the GeoIP database when deciding whether a result is domestic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<bool>,
    /// Country code considered "domestic".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_code: Option<Text>,
    /// Result IP ranges that trigger the fallback nameservers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipcidr: Vec<String>,
    /// Domains that always use the fallback nameservers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    /// Deprecated `geosite` categories that always use the fallback
    /// nameservers; prefer `nameserver-policy` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A `nameserver-policy` entry: either one upstream or a list of upstreams.
pub type NameserverPolicy = StringMap<OneOrMany<String>>;

/// The `dns` section.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Dns {
    /// Whether the built-in DNS server is enabled; when disabled the system
    /// resolver is used.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable: bool,
    /// Cache eviction algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_algorithm: Option<CacheAlgorithm>,
    /// Try HTTP/3 for DoH upstreams.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_h3: Option<bool>,
    /// Address the built-in DNS server listens on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<Text>,
    /// Allow AAAA queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
    /// How long to wait for an AAAA answer when racing dual-stack queries, in
    /// milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_timeout: Option<u64>,
    /// Resolve names through the `hosts` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_hosts: Option<bool>,
    /// Resolve names through the system hosts file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_system_hosts: Option<bool>,
    /// Route DNS connections according to `rules`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respect_rules: Option<bool>,
    /// Nameservers used to resolve the host names of the other nameservers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_nameserver: Vec<String>,
    /// Primary nameservers, used for direct connections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameserver: Vec<String>,
    /// Nameservers consulted when a result is considered non-domestic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<String>,
    /// Nameservers dedicated to resolving node server addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_server_nameserver: Vec<String>,
    /// Per-domain overrides for `proxy-server-nameserver`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_server_nameserver_policy: Option<NameserverPolicy>,
    /// Nameservers dedicated to resolving addresses for `DIRECT` connections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_nameserver: Vec<String>,
    /// Whether `direct-nameserver` also honours `nameserver-policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_nameserver_follow_policy: Option<bool>,
    /// Address allocation strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_mode: Option<EnhancedMode>,
    /// IPv4 fake-ip pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_range: Option<Text>,
    /// IPv6 fake-ip pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_range6: Option<Text>,
    /// Names that should not (or, in whitelist mode, should) receive a
    /// fake-ip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fake_ip_filter: Vec<String>,
    /// How `fake-ip-filter` is interpreted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter_mode: Option<FakeIpFilterMode>,
    /// TTL advertised for fake-ip answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_ttl: Option<u32>,
    /// Conditions that trigger the `fallback` nameservers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_filter: Option<FallbackFilter>,
    /// Query upstreams lazily when `fallback-filter` is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_lazy_query: Option<bool>,
    /// Per-domain nameserver overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameserver_policy: Option<NameserverPolicy>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
