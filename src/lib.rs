//! Typed Rust model and Serde (de)serialization for the
//! [mihomo](https://github.com/MetaCubeX/mihomo) (Clash.Meta) `config.yaml`.
//!
//! The crate deserializes a configuration file into strongly typed structures
//! and serializes it back with [`serde`] and [`serde_saphyr`]. It describes the
//! file format only, not what mihomo does with the values.
//!
//! ```
//! use serde_mihomo::Config;
//!
//! let yaml = r#"
//! mixed-port: 7890
//! mode: rule
//! proxies:
//!   - name: "ss1"
//!     type: ss
//!     server: example.com
//!     port: 443
//!     cipher: chacha20-ietf-poly1305
//!     password: "password"
//! rules:
//!   - MATCH,DIRECT
//! "#;
//!
//! let config = Config::from_yaml_str(yaml)?;
//! assert_eq!(config.general.mixed_port, Some(7890.into()));
//! assert_eq!(config.proxies[0].name, "ss1");
//!
//! // ... and write it back.
//! let round_tripped = Config::from_yaml_str(&config.to_yaml_string()?)?;
//! assert_eq!(config, round_tripped);
//! # Ok::<(), serde_mihomo::Error>(())
//! ```
//!
//! # Design
//!
//! * **Open schema.** Keys that are not modelled are kept in an `extra` map per
//!   section, and unknown enum values keep their text in `Other(String)`, so a
//!   configuration written for a newer mihomo release still parses and
//!   round-trips unchanged.
//! * **Lenient text.** [`Text`] accepts the placeholder notation used by the
//!   mihomo documentation (`server: [YOUR_SERVER_IP]`, `username: 1`) and
//!   dereferences to `str`; [`OneOrMany`] keeps "scalar or list" fields in the
//!   shape they were written in.
//! * **Deterministic output.** Ordered maps are used throughout, and values
//!   equal to their defaults are omitted.
//!
//! One module per configuration section: [`general`], [`tls`], [`dns`], [`tun`],
//! [`sniffer`], [`tunnel`], [`hosts`], [`proxy`], [`rule`] and [`listener`],
//! plus [`config`] for the root [`Config`] and [`value`] for the shared types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product names such as VMess, WireGuard or ShadowQUIC are not identifiers.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]

#[macro_use(derive)]
extern crate derive_aliases;

mod macros;

/// Derive aliases shared by every section of the configuration model.
///
/// The alias names are kept in one place so that the derive list of a section
/// can be changed crate-wide. `#[derive(..Alias)]` is expanded at compile time
/// by `derive_aliases`; it costs nothing at runtime.
///
/// * `SerdeEq` = `Debug + Clone + PartialEq + Eq + Serialize + Deserialize`,
///   for sections with required fields, which therefore have no meaningful
///   `Default`
/// * `SerdeEqDefault` = `SerdeEq + Default`, for sections where every field is
///   optional
pub(crate) mod derive_alias {
    derive_aliases::define! {
        SerdeEq = ::std::fmt::Debug, ::std::clone::Clone, ::std::cmp::PartialEq, ::std::cmp::Eq,
            ::serde::Serialize, ::serde::Deserialize;
        SerdeEqDefault = ..SerdeEq, ::std::default::Default;
    }
}

pub mod config;
pub mod dns;
pub mod error;
pub mod general;
pub mod hosts;
pub mod listener;
pub mod proxy;
pub mod rule;
pub mod sniffer;
pub mod tls;
pub mod tun;
pub mod tunnel;
pub mod value;

pub use crate::config::Config;
pub use crate::dns::{Dns, EnhancedMode, FakeIpFilterMode, FallbackFilter, NameserverPolicy};
pub use crate::error::{Error, Result};
pub use crate::general::{
    Experimental, ExternalControllerCors, FindProcessMode, General, GeoxUrl, LogLevel, Mode, Ports,
    Profile,
};
pub use crate::hosts::Hosts;
pub use crate::listener::{Listener, ListenerType, ListenerUser, ListenerUsers};
pub use crate::proxy::{
    HeaderMap, HealthCheck, HealthCheckConfig, LoadBalanceStrategy, ProviderOverride, Proxy,
    ProxyGroup, ProxyGroupType, ProxyOptions, ProxyProvider, ProxyProviderType, ProxyType,
    Reserved,
};
pub use crate::rule::{RuleBehavior, RuleFormat, RuleProvider, RuleProviderType, Rules, SubRules};
pub use crate::sniffer::{Sniff, Sniffer};
pub use crate::tls::{ClientAuthType, Tls};
pub use crate::tun::{CongestionController, Tun, TunStack};
pub use crate::tunnel::{DetailedTunnel, Tunnel};
pub use crate::value::{Extra, OneOrMany, StringMap, Text};

/// Everything you usually want when working with a mihomo configuration.
pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::{Config, Extra, OneOrMany, StringMap, Text};
}

#[cfg(test)]
mod tests {
    use super::{Config, Error, ListenerUsers, Mode, ProxyType};
    use std::path::PathBuf;

    /// Path of the reference `config.yaml` shipped with the repository.
    fn reference_config() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.yaml")
    }

    #[test]
    fn parses_the_reference_configuration() {
        let path = reference_config();
        if !path.exists() {
            eprintln!("skipping: {} is not available", path.display());
            return;
        }

        let config = Config::load(&path).expect("the reference configuration must deserialize");

        assert_eq!(config.general.mode, Some(Mode::Rule));
        assert_eq!(config.proxies.len(), 55);
        assert_eq!(config.proxy_groups.len(), 5);
        assert_eq!(config.proxy_providers.len(), 3);
        assert_eq!(config.rule_providers.len(), 4);
        assert_eq!(config.rules.len(), 10);
        assert_eq!(config.sub_rules.len(), 2);
        assert_eq!(config.listeners.len(), 20);

        // The template writes placeholders as one-element sequences; they read
        // back as plain text.
        let restls = config
            .proxies
            .iter()
            .find(|proxy| proxy.name == "ss-restls-tls13")
            .expect("ss-restls-tls13 is defined");
        assert_eq!(restls.proxy_type, ProxyType::Ss);
        assert_eq!(restls.server.as_deref(), Some("YOUR_SERVER_IP"));

        // Unmodelled, protocol specific keys are kept.
        assert_eq!(restls.plugin.as_deref(), Some("restls"));
        assert!(restls.plugin_opts.is_some());
        assert!(config.proxies.iter().any(|proxy| !proxy.extra.is_empty()));

        // Listeners accept both the list and the map form of `users`.
        let users = |name: &str| {
            config
                .listeners
                .iter()
                .find(|listener| listener.name == name)
                .and_then(|listener| listener.users.as_ref())
        };
        assert!(matches!(users("anytls-in-1"), Some(ListenerUsers::Map(_))));
        assert!(matches!(users("vmess-in-1"), Some(ListenerUsers::List(_))));
    }

    /// The property that matters for a format crate:
    /// `deserialize(serialize(x)) == x`, with nothing lost on the way.
    #[test]
    fn round_trips_the_reference_configuration_through_a_file() {
        let path = reference_config();
        if !path.exists() {
            eprintln!("skipping: {} is not available", path.display());
            return;
        }

        let parsed = Config::load(&path).expect("the reference configuration must deserialize");

        let written = std::env::temp_dir().join(format!(
            "serde-mihomo-round-trip-{}.yaml",
            std::process::id()
        ));
        parsed
            .save(&written)
            .expect("the parsed structure must serialize to a file");
        let parsed_again = Config::load(&written).expect("the written YAML must deserialize again");
        let _ = std::fs::remove_file(&written);

        assert_eq!(parsed, parsed_again);
    }

    #[test]
    fn round_trips_an_in_memory_document() {
        let parsed = Config::from_yaml_str(
            "mixed-port: 7890\n\
             mode: global\n\
             dns:\n  enable: true\n  nameserver: [1.1.1.1]\n\
             proxies:\n  - name: node\n    type: trojan\n    server: example.com\n    port: 443\n    password: p\n\
             proxy-groups:\n  - name: proxy\n    type: select\n    proxies: [node, DIRECT]\n\
             rules:\n  - MATCH,proxy\n",
        )
        .expect("the document must deserialize");
        assert_eq!(parsed.general.mode, Some(Mode::Global));
        assert_eq!(parsed.proxy_groups[0].proxies, ["node", "DIRECT"]);

        let emitted = parsed.to_yaml_string().expect("must serialize");
        assert_eq!(
            Config::from_yaml_str(&emitted).expect("must deserialize again"),
            parsed
        );
    }

    #[test]
    fn keeps_unknown_keys() {
        let config = Config::from_yaml_str("future-option: 42\nmode: rule\n").unwrap();
        assert_eq!(
            config.general.extra.get("future-option"),
            Some(&serde_json::json!(42))
        );
        assert!(
            config
                .to_yaml_string()
                .unwrap()
                .contains("future-option: 42")
        );
    }

    #[test]
    fn rejects_documents_that_do_not_match_the_model() {
        let error = Config::from_yaml_str("proxies:\n  - name: broken\n").unwrap_err();
        assert!(matches!(error, Error::Deserialize(_)));
        assert!(error.to_string().contains("invalid mihomo configuration"));
    }
}
