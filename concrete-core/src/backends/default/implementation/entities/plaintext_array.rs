use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::prelude::PlaintextCount;
use crate::specification::entities::markers::PlaintextArrayKind;
use crate::specification::entities::{AbstractEntity, PlaintextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of plaintexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextArray32(pub(crate) ImplPlaintextList<Vec<u32>>);
impl AbstractEntity for PlaintextArray32 {
    type Kind = PlaintextArrayKind;
}
impl PlaintextArrayEntity for PlaintextArray32 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PlaintextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of plaintexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextArray64(pub(crate) ImplPlaintextList<Vec<u64>>);
impl AbstractEntity for PlaintextArray64 {
    type Kind = PlaintextArrayKind;
}
impl PlaintextArrayEntity for PlaintextArray64 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PlaintextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
