//! Routing rules (`rules`, `sub-rules`) and rule providers.
//!
//! Rules are kept as their textual form, exactly like mihomo stores them, so
//! that every rule type (including ones added in the future) round-trips
//! unchanged. The typed surface of this module therefore focuses on the
//! `rule-providers` section.

use crate::macros::string_enum;
use crate::proxy::HeaderMap;
use crate::value::{Extra, StringMap, Text};

/// The ordered list evaluated by mihomo, top to bottom.
///
/// Each entry uses the usual `TYPE,PAYLOAD,POLICY` syntax, for example
/// `DOMAIN-SUFFIX,google.com,PROXY` or `MATCH,DIRECT`.
pub type Rules = Vec<String>;

/// Named rule lists referenced by `SUB-RULE` rules.
pub type SubRules = StringMap<Vec<String>>;

string_enum! {
    /// How the entries of a rule set are interpreted.
    pub enum RuleBehavior {
        /// Full mihomo rule syntax.
        Classical => "classical",
        /// A list of domains only.
        Domain => "domain",
        /// A list of CIDR blocks only.
        Ipcidr => "ipcidr",
    }
}

string_enum! {
    /// The on-disk format of a rule set.
    pub enum RuleFormat {
        /// A YAML document.
        Yaml => "yaml",
        /// A newline separated text file.
        Text => "text",
        /// The binary "mrs" format.
        Mrs => "mrs",
    }
}

string_enum! {
    /// How a rule provider obtains its rule set.
    pub enum RuleProviderType {
        /// Download the rule set from `url`.
        Http => "http",
        /// Read the rule set from a local file.
        File => "file",
        /// The rule set is declared inline in `payload`.
        Inline => "inline",
    }
}

/// An entry of the `rule-providers` map.
#[derive(..SerdeEqDefault)]
#[serde(rename_all = "kebab-case")]
pub struct RuleProvider {
    /// How the provider obtains its rules.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<RuleProviderType>,
    /// How the entries are interpreted; required for `http` and `file`
    /// providers that are not in the `mrs` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<RuleBehavior>,
    /// On-disk format of the rule set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleFormat>,
    /// Remote URL of the rule set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Text>,
    /// Local path of the rule set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Text>,
    /// Path inside `BundleMRS.7z`, used when the local file is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_in_bundle: Option<Text>,
    /// Refresh interval, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Proxy used to download the rule set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Text>,
    /// Maximum size of the downloaded file, in kilobytes; `0` means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
    /// Extra HTTP headers used when downloading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<HeaderMap>,
    /// Inline rule set (`inline` providers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<String>,
    /// Regular expression used to exclude rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_filter: Option<Text>,
    /// Keys this section does not model.
    #[serde(flatten)]
    pub extra: Extra,
}
