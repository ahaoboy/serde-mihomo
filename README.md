# serde-mihomo

Typed Rust model and Serde (de)serialization for the
[mihomo](https://github.com/MetaCubeX/mihomo) (Clash.Meta) `config.yaml`, built on
[`serde`](https://docs.rs/serde) and [`serde-saphyr`](https://docs.rs/serde-saphyr).

It describes the file format only — it does not emulate what mihomo does with the
values afterwards.

```toml
[dependencies]
serde-mihomo = { path = "." }
```

## Usage

```rust
use serde_mihomo::{Config, Result};

fn main() -> Result<()> {
    let config = Config::load("config.yaml")?;
    println!("{} proxies, {} rules", config.proxies.len(), config.rules.len());
    config.save("normalized.yaml")
}
```

### CLI

`serde-mihomo <FILE>` deserializes the file into `Config` and prints the YAML it
produces. Exit status: `0` success, `1` read/parse error, `2` usage error.

```console
$ serde-mihomo config.yaml
mixed-port: 10801
allow-lan: true
...
```

## Modules

One per configuration section: `general`, `tls`, `dns`, `tun`, `sniffer`,
`tunnel`, `hosts`, `proxy` (`proxies` / `proxy-groups` / `proxy-providers`),
`rule` (`rules` / `sub-rules` / `rule-providers`) and `listener`, plus `config`
for the root `Config` and `value` for the shared types.

## Design notes

- **Open schema.** Keys that are not modelled stay in an `extra` map on each
  section, and unknown enum values keep their text in `Other(String)`. A config
  written for a newer mihomo release still parses and round-trips unchanged.
- **Protocol options stay dynamic.** Shared proxy fields are typed; per-protocol
  blocks (`ws-opts`, `plugin-opts`, `reality-opts`, ...) are kept as maps.
- **Two text shapes.** `Text` accepts the template notation used by the mihomo
  docs (`server: [YOUR_SERVER_IP]`, `username: 1`) and dereferences to `str`;
  `OneOrMany<T>` preserves "scalar or list" fields in the shape they were written
  in.
- **Deterministic output.** Ordered maps, and values equal to their defaults are
  omitted, so `deserialize → serialize → deserialize` is stable.

## Testing

```console
$ cargo test && cargo clippy --all-targets
```

Tests live next to the code they cover. The reference `config.yaml` shipped here
is parsed and round-tripped through a real file; those tests skip themselves when
the file is absent.
