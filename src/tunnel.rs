//! The `tunnels` section: static port forwarding rules.

use crate::value::{Extra, OneOrMany, Text};

/// A tunnel written in long form.
#[derive(..SerdeEq)]
#[serde(rename_all = "kebab-case")]
pub struct DetailedTunnel {
    /// Network protocols forwarded by this tunnel; defaults to `tcp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<OneOrMany<String>>,
    /// Local `host:port` the tunnel listens on.
    pub address: String,
    /// Remote `host:port` the tunnel forwards to.
    pub target: String,
    /// Proxy or proxy group used to reach the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A tunnel entry.
///
/// mihomo accepts both a compact one-line form and a structured mapping:
///
/// ```yaml
/// tunnels:
///   - tcp/udp,127.0.0.1:6553,114.114.114.114:53,proxy
///   - network: [tcp, udp]
///     address: 127.0.0.1:7777
///     target: target.com
///     proxy: proxy
/// ```
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum Tunnel {
    /// The structured form.
    Detailed(DetailedTunnel),
    /// The one-line form: `network,address,target,proxy`.
    OneLine(String),
}

#[cfg(test)]
mod tests {
    use super::Tunnel;

    #[test]
    fn parses_both_forms() {
        let tunnels: Vec<Tunnel> =
            serde_saphyr::from_str("- tcp,127.0.0.1:6666,rds.mysql.com:3306,vpn").unwrap();
        assert!(matches!(tunnels[0], Tunnel::OneLine(_)));

        let tunnels: Vec<Tunnel> = serde_saphyr::from_str(
            "- network: [tcp, udp]\n  address: 127.0.0.1:7777\n  target: target.com\n  proxy: proxy\n",
        )
        .unwrap();
        assert!(
            matches!(&tunnels[0], Tunnel::Detailed(detailed) if detailed.address == "127.0.0.1:7777")
        );
    }
}
