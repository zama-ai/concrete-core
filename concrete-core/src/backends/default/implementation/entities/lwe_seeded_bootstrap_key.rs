use crate::commons::crypto::bootstrap::StandardSeededBootstrapKey as ImplStandardSeededBootstrapKey;
use crate::commons::math::random::CompressionSeed;
use crate::specification::entities::markers::{BinaryKeyDistribution, LweSeededBootstrapKeyKind};
use crate::specification::entities::{AbstractEntity, LweSeededBootstrapKeyEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a seeded LWE bootstrap key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededBootstrapKey32(pub(crate) ImplStandardSeededBootstrapKey<Vec<u32>>);
impl AbstractEntity for LweSeededBootstrapKey32 {
    type Kind = LweSeededBootstrapKeyKind;
}
impl LweSeededBootstrapKeyEntity for LweSeededBootstrapKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededBootstrapKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE bootstrap key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededBootstrapKey64(pub(crate) ImplStandardSeededBootstrapKey<Vec<u64>>);
impl AbstractEntity for LweSeededBootstrapKey64 {
    type Kind = LweSeededBootstrapKeyKind;
}
impl LweSeededBootstrapKeyEntity for LweSeededBootstrapKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededBootstrapKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
