use crate::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweCiphertextArrayKind;
use crate::specification::entities::{AbstractEntity, GlweCiphertextArrayEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an array of GLWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextArray32(pub(crate) ImplGlweList<Vec<u32>>);
impl AbstractEntity for GlweCiphertextArray32 {
    type Kind = GlweCiphertextArrayKind;
}
impl GlweCiphertextArrayEntity for GlweCiphertextArray32 {
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
pub(crate) enum GlweCiphertextArray32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an array of GLWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextArray64(pub(crate) ImplGlweList<Vec<u64>>);
impl AbstractEntity for GlweCiphertextArray64 {
    type Kind = GlweCiphertextArrayKind;
}
impl GlweCiphertextArrayEntity for GlweCiphertextArray64 {
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
pub(crate) enum GlweCiphertextArray64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
