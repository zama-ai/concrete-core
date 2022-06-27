use crate::commons::crypto::ggsw::StandardGgswSeededCiphertext as ImplStandardGgswSeededCiphertext;
use crate::commons::math::random::CompressionSeed;
use crate::specification::entities::markers::{BinaryKeyDistribution, GgswSeededCiphertextKind};
use crate::specification::entities::{AbstractEntity, GgswSeededCiphertextEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a seeded GGSW ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgswSeededCiphertext32(pub(crate) ImplStandardGgswSeededCiphertext<Vec<u32>>);
impl AbstractEntity for GgswSeededCiphertext32 {
    type Kind = GgswSeededCiphertextKind;
}
impl GgswSeededCiphertextEntity for GgswSeededCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GgswSeededCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a seeded GGSW ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgswSeededCiphertext64(pub(crate) ImplStandardGgswSeededCiphertext<Vec<u64>>);
impl AbstractEntity for GgswSeededCiphertext64 {
    type Kind = GgswSeededCiphertextKind;
}
impl GgswSeededCiphertextEntity for GgswSeededCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GgswSeededCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
