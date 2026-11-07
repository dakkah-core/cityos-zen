//! Lossless map-only decoding for untrusted protocol structures.
use serde::{Deserialize, Deserializer};

pub(crate) struct Object<T>(pub T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Object<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }

        deserializer.deserialize_map(Visitor(std::marker::PhantomData))
    }
}

pub(crate) fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Object::<T>::deserialize(deserializer).map(|Object(value)| value)
}

#[cfg(test)]
mod tests {
    use super::Object;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        value: u8,
    }

    #[test]
    fn derived_structs_require_json_objects() {
        let Object(entry) = serde_json::from_str::<Object<Entry>>(r#"{"value":1}"#).unwrap();
        assert_eq!(entry.value, 1);
        assert!(serde_json::from_str::<Object<Entry>>("[1]").is_err());
    }
}
