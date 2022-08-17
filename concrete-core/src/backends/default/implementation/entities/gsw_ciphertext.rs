use crate::commons::crypto::gsw::GswCiphertext as ImplGswCiphertext;
use crate::specification::entities::markers::GswCiphertextKind;
use crate::specification::entities::{AbstractEntity, GswCiphertextEntity};
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a GSW ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GswCiphertext32(pub(crate) ImplGswCiphertext<Vec<u32>, u32>);

impl AbstractEntity for GswCiphertext32 {
    type Kind = GswCiphertextKind;
}

impl GswCiphertextEntity for GswCiphertext32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GswCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a GSW ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GswCiphertext64(pub(crate) ImplGswCiphertext<Vec<u64>, u64>);

impl AbstractEntity for GswCiphertext64 {
    type Kind = GswCiphertextKind;
}

impl GswCiphertextEntity for GswCiphertext64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GswCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
