use crate::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweCiphertextVectorKind;
use crate::specification::entities::{AbstractEntity, GlweCiphertextVectorEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of GLWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextVector32(pub(crate) ImplGlweList<Vec<u32>>);
impl AbstractEntity for GlweCiphertextVector32 {
    type Kind = GlweCiphertextVectorKind;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextVector64(pub(crate) ImplGlweList<Vec<u64>>);
impl AbstractEntity for GlweCiphertextVector64 {
    type Kind = GlweCiphertextVectorKind;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
