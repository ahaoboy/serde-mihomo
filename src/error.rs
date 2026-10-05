//! Error type returned by the crate.

use std::fmt;
use std::path::PathBuf;

/// The error type returned when loading, parsing or serializing a mihomo
/// configuration.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred while reading or writing a configuration file.
    Io {
        /// Path of the file that could not be accessed, when known.
        path: Option<PathBuf>,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The YAML document could not be deserialized into the configuration
    /// model.
    Deserialize(serde_saphyr::Error),
    /// The configuration model could not be serialized back to YAML.
    Serialize(serde_saphyr::SerializeError),
}

impl Error {
    /// Creates an [`Error::Io`] from a path and the underlying I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: Some(path.into()),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => match path {
                Some(path) => write!(f, "failed to access `{}`: {source}", path.display()),
                None => write!(f, "I/O error: {source}"),
            },
            Self::Deserialize(error) => write!(f, "invalid mihomo configuration: {error}"),
            Self::Serialize(error) => write!(f, "failed to serialize configuration: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Deserialize(error) => Some(error),
            Self::Serialize(error) => Some(error),
        }
    }
}

impl From<serde_saphyr::Error> for Error {
    fn from(error: serde_saphyr::Error) -> Self {
        Self::Deserialize(error)
    }
}

impl From<serde_saphyr::SerializeError> for Error {
    fn from(error: serde_saphyr::SerializeError) -> Self {
        Self::Serialize(error)
    }
}

/// Convenience alias for a `Result` carrying the crate [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
