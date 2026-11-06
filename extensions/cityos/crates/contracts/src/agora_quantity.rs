//! Data-only quantity protocol. Identities and facts are caller assertions.
use serde::{Deserialize, Deserializer, Serialize};

pub const KIND: &str = "agora-cart-quantity";
pub const PROFILE: &str = "cityos.zen.agora-cart-quantity.v1";

/// Explicit resource contract for the isolated quantity evaluator. Host
/// registration and qualification must bind this exact profile identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionProfileV1 {
    pub id: &'static str,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_items: usize,
    pub max_wall_clock_millis: u64,
    pub max_address_space_bytes: u64,
    pub max_cpu_seconds: u64,
    pub max_open_files: u64,
    pub max_processes: u8,
    pub network_enabled: bool,
}

pub const EXECUTION_PROFILE: ExecutionProfileV1 = ExecutionProfileV1 {
    id: "cityos.zen.agora-cart-quantity.execution.v1",
    max_request_bytes: 4 * 1024 * 1024,
    max_response_bytes: 4_096,
    max_items: 10_000,
    max_wall_clock_millis: 5_000,
    max_address_space_bytes: 512 * 1024 * 1024,
    max_cpu_seconds: 3,
    max_open_files: 32,
    max_processes: 1,
    network_enabled: false,
};

pub const MAX_REQUEST_BYTES: usize = EXECUTION_PROFILE.max_request_bytes;
pub const MAX_ITEMS: usize = EXECUTION_PROFILE.max_items;

// Derived struct deserializers accept sequences; require maps at every level.
pub struct Object<T>(pub T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        d.deserialize_map(Visitor(std::marker::PhantomData))
    }
}
fn required_option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    pub kind: String,
    pub profile: String,
    pub items: Vec<Object<Item>>,
    pub rule: Object<Rule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item { pub sku: String, pub quantity: u64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    pub rule_id: String,
    pub revision_digest: String,
    pub rule_type: String,
    pub status: String,
    #[serde(deserialize_with = "required_option")]
    pub target_sku: Option<String>,
    pub max_quantity: u64,
}
/// A calculation only: the echoed identifiers are unverified caller assertions.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub kind: &'static str,
    pub profile: &'static str,
    pub execution_profile: &'static str,
    pub source_sha256: String,
    pub rule_id: String,
    pub revision_digest: String,
    pub matching_quantity: u64,
    pub max_quantity: u64,
    pub within_limit: bool,
}
