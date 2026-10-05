//! The `tun` section.

use crate::macros::string_enum;
use crate::value::{Extra, Text};

string_enum! {
    /// The userspace network stack implementation used by the TUN device.
    pub enum TunStack {
        /// The `gVisor` stack (default).
        Gvisor => "gvisor",
        /// The system stack.
        System => "system",
        /// A hybrid of the system and `gVisor` stacks.
        Mixed => "mixed",
        /// The legacy `mips` stack kept for compatibility with old
        /// configurations.
        Mips => "mips",
    }
}

string_enum! {
    /// TCP congestion control algorithm.
    pub enum CongestionController {
        /// CUBIC.
        Cubic => "cubic",
        /// Reno.
        Reno => "reno",
        /// BBR.
        Bbr => "bbr",
        /// BBR v3.
        Bbr3 => "bbr3",
    }
}

/// The `tun` section.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Tun {
    /// Enable the TUN inbound.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable: bool,
    /// Explicit TUN device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Text>,
    /// Network stack implementation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<TunStack>,
    /// Addresses whose DNS traffic is hijacked by the DNS server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_hijack: Vec<String>,
    /// Detect the outbound interface automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_detect_interface: Option<bool>,
    /// Configure the routing table automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_route: Option<bool>,
    /// Maximum transmission unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Enable generic segmentation offload (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gso: Option<bool>,
    /// Maximum GSO packet size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gso_max_size: Option<u32>,
    /// Configure `iptables` automatically to redirect TCP connections (Linux
    /// only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_redirect: Option<bool>,
    /// Route every connection through the TUN device to prevent leaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_route: Option<bool>,
    /// Disable ICMP forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_icmp_forwarding: Option<bool>,
    /// TCP congestion control algorithm; only effective on the `mips` stack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_controller: Option<CongestionController>,
    /// Rule sets whose destination CIDRs are routed through the TUN device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_address_set: Vec<String>,
    /// Rule sets whose destination CIDRs bypass the TUN device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_exclude_address_set: Vec<String>,
    /// Custom IPv4/IPv6 routes to install when `auto-route` is enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_address: Vec<String>,
    /// Deprecated IPv4 route list; use `route-address` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet4_route_address: Vec<String>,
    /// Deprecated IPv6 route list; use `route-address` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet6_route_address: Vec<String>,
    /// Enable endpoint independent NAT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_independent_nat: Option<bool>,
    /// Interfaces that are routed; mutually exclusive with
    /// `exclude-interface`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_interface: Vec<String>,
    /// Interfaces that are not routed; mutually exclusive with
    /// `include-interface`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_interface: Vec<String>,
    /// UIDs whose traffic is routed (Linux only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_uid: Vec<u32>,
    /// UID ranges whose traffic is routed, for example `1000:9999`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_uid_range: Vec<String>,
    /// UIDs whose traffic is not routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_uid: Vec<u32>,
    /// UID ranges whose traffic is not routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_uid_range: Vec<String>,
    /// MAC addresses whose traffic is routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_mac_address: Vec<String>,
    /// MAC addresses whose traffic is not routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_mac_address: Vec<String>,
    /// Android user ids whose traffic is routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_android_user: Vec<u32>,
    /// Android package names whose traffic is routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_package: Vec<String>,
    /// Android package names whose traffic is not routed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_package: Vec<String>,
    /// Pre-opened TUN file descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_descriptor: Option<i32>,
    /// Idle timeout of TUN UDP sessions, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<u32>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
