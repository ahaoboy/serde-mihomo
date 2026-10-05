//! The root [`Config`] type and the loading/saving helpers.

use std::io::{Read, Write};
use std::path::Path;

use crate::dns::Dns;
use crate::error::{Error, Result};
use crate::general::{Experimental, General, Profile};
use crate::hosts::Hosts;
use crate::listener::Listener;
use crate::proxy::{Proxy, ProxyGroup, ProxyProvider};
use crate::rule::{RuleProvider, Rules, SubRules};
use crate::sniffer::Sniffer;
use crate::tls::Tls;
use crate::tun::Tun;
use crate::tunnel::Tunnel;
use crate::value::StringMap;

/// A complete mihomo (`Clash.Meta`) configuration file.
///
/// The general options live in [`Config::general`]; every other top level
/// section is exposed as its own field. Keys that are not modelled never make
/// deserialization fail: they are kept in the `extra` map of the enclosing
/// section, so a configuration written for a newer mihomo release round-trips
/// unchanged.
///
/// ```no_run
/// use serde_mihomo::Config;
///
/// let config = Config::load("config.yaml")?;
/// println!("{} proxies", config.proxies.len());
/// let yaml = config.to_yaml_string()?;
/// # Ok::<(), serde_mihomo::Error>(())
/// ```
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Ports, authentication, controller, log level and the other general
    /// options.
    #[serde(flatten)]
    pub general: General,
    /// TLS material used by the external controller and TLS listeners.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    /// Experimental feature flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
    /// Static host name mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Hosts>,
    /// Persistence of runtime state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// The TUN inbound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun: Option<Tun>,
    /// Domain sniffing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffer: Option<Sniffer>,
    /// Static port forwarding rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<Tunnel>,
    /// The built-in DNS server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// Proxy nodes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<Proxy>,
    /// Proxy groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_groups: Vec<ProxyGroup>,
    /// Named proxy providers.
    #[serde(default, skip_serializing_if = "crate::value::is_empty_map")]
    pub proxy_providers: StringMap<ProxyProvider>,
    /// Named rule providers.
    #[serde(default, skip_serializing_if = "crate::value::is_empty_map")]
    pub rule_providers: StringMap<RuleProvider>,
    /// The rule list, evaluated top to bottom.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Rules,
    /// Named rule lists referenced by `SUB-RULE` rules.
    #[serde(default, skip_serializing_if = "crate::value::is_empty_map")]
    pub sub_rules: SubRules,
    /// Additional inbound listeners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Listener>,
}

impl Config {
    /// Parses a configuration from a YAML string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Deserialize`] when the document is not valid YAML or
    /// does not match the configuration model.
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        Ok(serde_saphyr::from_str(yaml)?)
    }

    /// Parses a configuration from a UTF-8 YAML byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Deserialize`] when the document is not valid YAML or
    /// does not match the configuration model.
    pub fn from_yaml_slice(yaml: &[u8]) -> Result<Self> {
        Ok(serde_saphyr::from_slice(yaml)?)
    }

    /// Parses a configuration from any reader.
    ///
    /// Unlike [`Config::from_yaml_str`] the input is parsed incrementally and is
    /// never buffered in full.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Deserialize`] when the document is not valid YAML or
    /// does not match the configuration model.
    pub fn from_yaml_reader<R: Read>(reader: R) -> Result<Self> {
        Ok(serde_saphyr::from_reader(reader)?)
    }

    /// Reads and parses a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read and
    /// [`Error::Deserialize`] when its content is invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path).map_err(|error| Error::io(path, error))?;
        Self::from_yaml_reader(std::io::BufReader::new(file))
    }

    /// Serializes the configuration to a YAML string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialize`] when the configuration cannot be written.
    pub fn to_yaml_string(&self) -> Result<String> {
        Ok(serde_saphyr::to_string(self)?)
    }

    /// Serializes the configuration as YAML into any writer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialize`] when the configuration cannot be written.
    pub fn write_yaml<W: Write>(&self, mut writer: W) -> Result<()> {
        Ok(serde_saphyr::to_io_writer(&mut writer, self)?)
    }

    /// Serializes the configuration into a file, creating or truncating it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be created and
    /// [`Error::Serialize`] when the configuration cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let file = std::fs::File::create(path).map_err(|error| Error::io(path, error))?;
        self.write_yaml(std::io::BufWriter::new(file))
    }
}
