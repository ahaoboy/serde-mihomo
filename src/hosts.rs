//! The `hosts` section: a static, `/etc/hosts`-like mapping.

use crate::value::{OneOrMany, StringMap};

/// Static host entries.
///
/// Values may be a single address or a list of addresses, and mihomo also
/// accepts two special forms:
///
/// * `lan` — expands to every address of the local network interfaces;
/// * another host name — used as an alias.
///
/// ```yaml
/// hosts:
///   '*.mihomo.dev': 127.0.0.1
///   test.com: [1.1.1.1, 2.2.2.2]
///   home.lan: lan
///   baidu.com: google.com
/// ```
pub type Hosts = StringMap<OneOrMany<String>>;
