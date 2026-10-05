//! Shared value types used by the configuration model.
//!
//! Two types cover the "one value or a list of values" notation mihomo uses:
//! [`Text`] flattens it (`[a, b]` becomes the text `a,b`) for fields that expect
//! a single scalar, while [`OneOrMany`] preserves it so the list form is written
//! back unchanged.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;

use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::{Serialize, Serializer};

/// A textual YAML scalar, written leniently.
///
/// The reference `config.yaml` published by mihomo is a template containing
/// entries such as `server: [YOUR_SERVER_IP]` or `username: 1`, which are not
/// plain strings. `Text` accepts a string, number or boolean scalar, or a
/// sequence (joined with `,`), and stores the result as text. It dereferences to
/// `str`, so it is used like a string.
///
/// ```
/// # use serde_mihomo::Text;
/// let text: Text = serde_saphyr::from_str("[YOUR_SERVER_IP]")?;
/// assert_eq!(&*text, "YOUR_SERVER_IP");
/// assert_eq!(text.as_str(), "YOUR_SERVER_IP");
/// # Ok::<(), serde_saphyr::Error>(())
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Text(String);

impl Text {
    /// Wraps an existing string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the text as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Text {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl From<String> for Text {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Text {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<Text> for String {
    fn from(value: Text) -> Self {
        value.0
    }
}

/// Compares against a plain string, so `text == "value"` works.
impl PartialEq<str> for Text {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Text {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Collects a single scalar as a string.
struct Scalar;

impl Visitor<'_> for Scalar {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scalar")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.to_owned())
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.to_string())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.to_string())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.to_string())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(value.to_string())
    }
}

/// One element of a [`Text`] sequence.
struct ScalarText(String);

impl<'de> Deserialize<'de> for ScalarText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Scalar).map(Self)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Accepts a scalar or a sequence of scalars and joins the latter.
        struct TextVisitor;

        impl<'de> Visitor<'de> for TextVisitor {
            type Value = Text;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a scalar or a sequence of scalars")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Text(value.to_owned()))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(Text(value.to_string()))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Text(value.to_string()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Text(value.to_string()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(Text(value.to_string()))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut parts = Vec::with_capacity(seq.size_hint().unwrap_or(1));
                while let Some(ScalarText(part)) = seq.next_element::<ScalarText>()? {
                    parts.push(part);
                }
                Ok(Text(parts.join(",")))
            }
        }

        deserializer.deserialize_any(TextVisitor)
    }
}

/// A YAML scalar that may optionally be given as a sequence.
///
/// ```yaml
/// header:
///   User-Agent: "mihomo/1.19.0"      # One
///   Accept:                          # Many
///     - application/vnd.github.v3.raw
/// ```
#[derive(..SerdeEq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),
    /// An explicit list of values.
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// Returns the values as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values.as_slice(),
        }
    }

    /// Returns the number of stored values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns `true` when no value is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Iterates over the stored values.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(values: Vec<T>) -> Self {
        Self::Many(values)
    }
}

impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(value) => vec![value].into_iter(),
            Self::Many(values) => values.into_iter(),
        }
    }
}

impl<'a, T> IntoIterator for &'a OneOrMany<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// An ordered string keyed map, used so that serializing a [`Config`] produces
/// deterministic output.
///
/// [`Config`]: crate::Config
pub type StringMap<T> = BTreeMap<String, T>;

/// Free-form YAML mapping attached to a configuration section.
///
/// Every section keeps the keys it does not model in an `extra` field, so a
/// configuration written for a newer mihomo release survives a
/// deserialize → serialize round-trip untouched.
pub type Extra = serde_json::Map<String, serde_json::Value>;

/// Returns `true` when the given ordered map is empty.
///
/// Used as a `skip_serializing_if` predicate for [`StringMap`] fields, whose
/// type alias cannot be named without its generic argument.
#[must_use]
pub fn is_empty_map<T>(map: &BTreeMap<String, T>) -> bool {
    map.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{OneOrMany, Text};

    #[test]
    fn text_accepts_scalars_and_sequences() {
        let plain: Text = serde_saphyr::from_str("hello").unwrap();
        assert_eq!(plain, "hello");

        let quoted: Text = serde_saphyr::from_str("\"a: b\"").unwrap();
        assert_eq!(quoted.as_str(), "a: b");

        let number: Text = serde_saphyr::from_str("1").unwrap();
        assert_eq!(number, "1");

        let flag: Text = serde_saphyr::from_str("true").unwrap();
        assert_eq!(flag, "true");

        let sequence: Text = serde_saphyr::from_str("[YOUR_SERVER_IP]").unwrap();
        assert_eq!(sequence, "YOUR_SERVER_IP");

        let list: Text = serde_saphyr::from_str("[a, b]").unwrap();
        assert_eq!(list, "a,b");
    }

    #[test]
    fn text_rejects_mappings() {
        assert!(serde_saphyr::from_str::<Text>("{a: b}").is_err());
    }

    #[test]
    fn text_round_trips() {
        let text = Text::new("value");
        assert_eq!(serde_saphyr::to_string(&text).unwrap().trim(), "value");
    }

    #[test]
    fn one_or_many_accepts_scalar_and_sequence() {
        let one: OneOrMany<String> = serde_saphyr::from_str("value").unwrap();
        assert_eq!(one.as_slice(), ["value"]);

        let many: OneOrMany<String> = serde_saphyr::from_str("[a, b]").unwrap();
        assert_eq!(many.as_slice(), ["a", "b"]);
    }

    #[test]
    fn one_or_many_round_trips() {
        let many = OneOrMany::Many(vec![1u16, 2, 3]);
        let yaml = serde_saphyr::to_string(&many).unwrap();
        let back: OneOrMany<u16> = serde_saphyr::from_str(&yaml).unwrap();
        assert_eq!(many, back);
    }
}
