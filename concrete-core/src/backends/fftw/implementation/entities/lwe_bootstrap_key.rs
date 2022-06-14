use crate::backends::fftw::private::crypto::bootstrap::FourierBootstrapKey;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::specification::entities::markers::{BinaryKeyDistribution, LweBootstrapKeyKind};
use crate::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_fftw::array::AlignedVec;
#[cfg(feature = "backend_fftw_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE bootstrap key with 32 bits of precision, in the fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierLweBootstrapKey32(pub(crate) FourierBootstrapKey<AlignedVec<Complex64>, u32>);
impl AbstractEntity for FftwFourierLweBootstrapKey32 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for FftwFourierLweBootstrapKey32 {
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
}

#[cfg(feature = "backend_fftw_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftwFourierLweBootstrapKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE bootstrap key with 64 bits of precision, in the fourier domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierLweBootstrapKey64(pub(crate) FourierBootstrapKey<AlignedVec<Complex64>, u64>);
impl AbstractEntity for FftwFourierLweBootstrapKey64 {
    type Kind = LweBootstrapKeyKind;
}
impl LweBootstrapKeyEntity for FftwFourierLweBootstrapKey64 {
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
}

#[cfg(feature = "backend_fftw_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftwFourierLweBootstrapKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
