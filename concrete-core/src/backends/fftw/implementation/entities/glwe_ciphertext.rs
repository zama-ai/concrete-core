use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::specification::entities::markers::{BinaryKeyDistribution, GlweCiphertextKind};
use crate::specification::entities::{AbstractEntity, GlweCiphertextEntity};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_fftw::array::AlignedVec;
#[cfg(feature = "backend_fftw_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a Fourier GLWE ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGlweCiphertext32(
    pub(crate) FourierGlweCiphertext<AlignedVec<Complex64>, u32>,
);
impl AbstractEntity for FftwFourierGlweCiphertext32 {
    type Kind = GlweCiphertextKind;
}
impl GlweCiphertextEntity for FftwFourierGlweCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_fftw_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftwFourierGlweCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a Fourier GLWE ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGlweCiphertext64(
    pub(crate) FourierGlweCiphertext<AlignedVec<Complex64>, u64>,
);
impl AbstractEntity for FftwFourierGlweCiphertext64 {
    type Kind = GlweCiphertextKind;
}
impl GlweCiphertextEntity for FftwFourierGlweCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_fftw_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FftwFourierGlweCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
