use crate::commons::crypto::glwe::GlweSeededList as ImplGlweSeededList;
use crate::commons::math::random::CompressionSeed;
use crate::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweSeededCiphertextArrayKind;
use crate::specification::entities::{AbstractEntity, GlweSeededCiphertextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of GLWE seeded ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertextArray32(pub(crate) ImplGlweSeededList<Vec<u32>>);
impl AbstractEntity for GlweSeededCiphertextArray32 {
    type Kind = GlweSeededCiphertextArrayKind;
}
impl GlweSeededCiphertextArrayEntity for GlweSeededCiphertextArray32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of GLWE seeded ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertextArray64(pub(crate) ImplGlweSeededList<Vec<u64>>);
impl AbstractEntity for GlweSeededCiphertextArray64 {
    type Kind = GlweSeededCiphertextArrayKind;
}
impl GlweSeededCiphertextArrayEntity for GlweSeededCiphertextArray64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
