use crate::commons::crypto::encoding::CleartextList as ImplCleartextList;
use crate::prelude::CleartextCount;
use crate::specification::entities::markers::CleartextArrayKind;
use crate::specification::entities::{AbstractEntity, CleartextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of cleartexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextArray32(pub(crate) ImplCleartextList<Vec<u32>>);
impl AbstractEntity for CleartextArray32 {
    type Kind = CleartextArrayKind;
}
impl CleartextArrayEntity for CleartextArray32 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of cleartexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextArray64(pub(crate) ImplCleartextList<Vec<u64>>);
impl AbstractEntity for CleartextArray64 {
    type Kind = CleartextArrayKind;
}
impl CleartextArrayEntity for CleartextArray64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array floating point cleartext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct CleartextArrayF64(pub(crate) ImplCleartextList<Vec<f64>>);
impl AbstractEntity for CleartextArrayF64 {
    type Kind = CleartextArrayKind;
}
impl CleartextArrayEntity for CleartextArrayF64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextArrayF64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
