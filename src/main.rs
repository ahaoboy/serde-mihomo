//! A minimal command line front end for the [`serde_mihomo`] crate.
//!
//! The program takes a single path, deserializes the file into the typed
//! [`Config`] structure and prints the resulting YAML document to stdout:
//!
//! ```text
//! serde-mihomo <FILE>
//! ```
//!
//! Nothing else happens: the input is parsed and written back, so a
//! `serde-mihomo config.yaml | diff - config.yaml` shows how the parsed
//! structure maps onto YAML.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_mihomo::Config;

const USAGE: &str = "\
serde-mihomo - deserialize and re-serialize a mihomo (Clash.Meta) config.yaml

USAGE:
    serde-mihomo <FILE>

ARGUMENTS:
    <FILE>           Path of the configuration file to read

OPTIONS:
    -h, --help       Print this message
    -V, --version    Print the crate version

The file is deserialized into the typed configuration structure and the result
is printed to stdout as YAML.

EXIT STATUS:
    0  success
    1  the file could not be read or parsed
    2  bad command line usage
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-V" | "--version"))
    {
        println!("serde-mihomo {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let [path] = args.as_slice() else {
        eprintln!("error: expected exactly one file path");
        eprint!("\n{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(path);

    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {}", path.display());
            eprintln!("  {error}");
            return ExitCode::from(1);
        }
    };

    match config.to_yaml_string() {
        Ok(yaml) => {
            print!("{yaml}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}
