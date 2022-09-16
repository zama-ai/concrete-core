use crate::backends::ntt::private::crypto::ggsw::NttGgswCiphertext;
use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::specification::entities::markers::GgswCiphertextKind;
use crate::specification::entities::{AbstractEntity, GgswCiphertextEntity};

/// A structure representing a GGSW ciphertext with 64 bits of precision in the NTT domain.
/// Note: The name `NttFourierGgswCiphertext64` refers to the bit size of the coefficients in the
/// standard domain. Coefficients in the NTT domain are represented on 128 bits in order to
/// easily support modular multiplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierGgswCiphertext64(pub(crate) NttGgswCiphertext<Vec<ModQ<u128>>>);
impl AbstractEntity for NttFourierGgswCiphertext64 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for NttFourierGgswCiphertext64 {
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
}

/// A structure representing a GGSW ciphertext with 32 bits of precision in the NTT domain.
/// Note: The name `NttFourierGgswCiphertext32` refers to the bit size of the coefficients in the
/// standard domain. Coefficients in the NTT domain are represented on 64 bits in order to
/// easily support modular multiplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierGgswCiphertext32(pub(crate) NttGgswCiphertext<Vec<ModQ<u64>>>);
impl AbstractEntity for NttFourierGgswCiphertext32 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for NttFourierGgswCiphertext32 {
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
}