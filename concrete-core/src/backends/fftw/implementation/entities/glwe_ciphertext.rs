use concrete_fftw::array::AlignedVec;
#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};

use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::Complex64;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

use crate::specification::entities::markers::{BinaryKeyDistribution, GlweCiphertextKind};
use crate::specification::entities::{AbstractEntity, GlweCiphertextEntity};

/// A structure representing a Fourier GLWE ciphertext with 32 bits of precision.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
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

/// A structure representing a Fourier GLWE ciphertext with 64 bits of precision.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
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
