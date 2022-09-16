// #[cfg(feature = "serde_serialize")]
// use serde::{Deserialize, Serialize};

use crate::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::prelude::{GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweCiphertextKind;
use crate::specification::entities::{AbstractEntity, GlweCiphertextEntity};

/// A structure representing a GLWE ciphertext with 32 bits of precision in the NTT domain.
/// We use u64 (u128) for 32bit (64bit, resp.) ciphertexts to be able to represent
/// the product of two numbers before modular reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierGlweCiphertext32(pub(crate) NttGlweCiphertext<Vec<ModQ<u64>>>);
impl AbstractEntity for NttFourierGlweCiphertext32 {
    type Kind = GlweCiphertextKind;
}
impl GlweCiphertextEntity for NttFourierGlweCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a GLWE ciphertext with 64 bits of precision in the NTT domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierGlweCiphertext64(pub(crate) NttGlweCiphertext<Vec<ModQ<u128>>>);
impl AbstractEntity for NttFourierGlweCiphertext64 {
    type Kind = GlweCiphertextKind;
}
impl GlweCiphertextEntity for NttFourierGlweCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
