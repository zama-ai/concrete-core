use crate::backends::fftw::private::crypto::secret::FourierGlweSecretKey;
use crate::backends::fftw::private::math::fft::{AlignedVec, Complex64};
use crate::prelude::markers::TensorProductKeyDistribution;
use crate::prelude::BinaryTensorProductKeyKind;
use crate::specification::entities::markers::GlweSecretKeyKind;
use crate::specification::entities::{AbstractEntity, GlweSecretKeyEntity};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
#[cfg(feature = "serde_serialize")]
use serde::{Deserialize, Serialize};

/// A structure representing a GLWE tensored secret key with 32 bits of precision in the Fourier
/// domain.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGlweTensorProductSecretKey32(
    pub(crate) FourierGlweSecretKey<BinaryTensorProductKeyKind, AlignedVec<Complex64>, u32>,
);
impl AbstractEntity for FftwFourierGlweTensorProductSecretKey32 {
    type Kind = GlweSecretKeyKind;
}
impl GlweSecretKeyEntity for FftwFourierGlweTensorProductSecretKey32 {
    type KeyDistribution = TensorProductKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a GLWE tensor product secret key with 64 bits of precision in the
/// Fourier domain.
#[cfg_attr(feature = "serde_serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGlweTensorProductSecretKey64(
    pub(crate) FourierGlweSecretKey<BinaryTensorProductKeyKind, AlignedVec<Complex64>, u64>,
);
impl AbstractEntity for FftwFourierGlweTensorProductSecretKey64 {
    type Kind = GlweSecretKeyKind;
}
impl GlweSecretKeyEntity for FftwFourierGlweTensorProductSecretKey64 {
    type KeyDistribution = TensorProductKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
