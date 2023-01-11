use crate::backends::ntt::private::crypto::bootstrap::ntt::NttBootstrapKey;
use crate::backends::ntt::private::math::mod_q::ModQ;
use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::specification::entities::markers::LweBootstrapKeyKind;
use crate::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};

/// A structure representing an LWE bootstrap key with 32 bits of precision, in the NTT domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierLweBootstrapKey32(pub(crate) NttBootstrapKey<Vec<ModQ<u64>>>);
impl AbstractEntity for NttFourierLweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for NttFourierLweBootstrapKey32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}

/// A structure representing an LWE bootstrap key with 64 bits of precision, in the NTT domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttFourierLweBootstrapKey64(pub(crate) NttBootstrapKey<Vec<ModQ<u128>>>);
impl AbstractEntity for NttFourierLweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for NttFourierLweBootstrapKey64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.input_lwe_dimension()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.base_log()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.level_count()
    }
}