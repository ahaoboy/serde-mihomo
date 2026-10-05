//! Internal helper macros shared across the crate.

/// Implements the common boilerplate of a "string enum": an enum whose variants
/// map to kebab-case YAML scalars and which preserves unknown values verbatim.
///
/// Unknown values are *not* rejected; they are stored in the trailing
/// `Other(String)` variant, which makes the model tolerant of configuration
/// written for newer mihomo releases while still round-tripping unchanged.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $literal:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(
            ::std::fmt::Debug,
            ::std::clone::Clone,
            ::std::cmp::PartialEq,
            ::std::cmp::Eq,
        )]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
            /// A value that is not part of the documented set.
            ///
            /// Kept as-is so that configuration authored for a newer mihomo
            /// release can be read and written back without loss.
            Other(::std::string::String),
        }

        impl $name {
            /// Returns the canonical YAML spelling of this value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $($name::$variant => $literal,)+
                    $name::Other(other) => other.as_str(),
                }
            }

            /// Returns `true` when the value is not part of the documented set.
            #[must_use]
            pub fn is_unknown(&self) -> bool {
                matches!(self, $name::Other(_))
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::std::convert::Infallible;

            fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
                match value {
                    $($literal => Ok($name::$variant),)+
                    other => Ok($name::Other(other.to_owned())),
                }
            }
        }

        impl ::std::convert::From<::std::string::String> for $name {
            fn from(value: ::std::string::String) -> Self {
                match value.parse() {
                    ::std::result::Result::Ok(parsed) => parsed,
                    ::std::result::Result::Err(never) => match never {},
                }
            }
        }

        impl ::std::convert::From<&str> for $name {
            fn from(value: &str) -> Self {
                value.to_owned().into()
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<__S>(&self, serializer: __S) -> ::std::result::Result<__S::Ok, __S::Error>
            where
                __S: ::serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<__D>(deserializer: __D) -> ::std::result::Result<Self, __D::Error>
            where
                __D: ::serde::Deserializer<'de>,
            {
                let raw = <::std::borrow::Cow<'de, str> as ::serde::Deserialize<'de>>::deserialize(
                    deserializer,
                )?;
                ::std::result::Result::Ok(match raw.as_ref().parse() {
                    ::std::result::Result::Ok(parsed) => parsed,
                    ::std::result::Result::Err(never) => match never {},
                })
            }
        }
    };
}

pub(crate) use string_enum;
