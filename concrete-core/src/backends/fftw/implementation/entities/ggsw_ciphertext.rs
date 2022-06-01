use crate::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext;
use crate::commons::math::fft::Complex64;
use crate::specification::entities::markers::{BinaryKeyDistribution, GgswCiphertextKind};
use crate::specification::entities::{AbstractEntity, GgswCiphertextEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_fftw::array::AlignedVec;

/// A structure representing a GGSW ciphertext with 64 bits of precision in the Fourier domain.
/// Note: The name `FftwFourierGgswCiphertext64` refers to the bit size of the coefficients in the
/// standard domain. Complex coefficients (eg in the Fourier domain) are always represented on 64
/// bits.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGgswCiphertext64(
    pub(crate) FourierGgswCiphertext<AlignedVec<Complex64>, u64>,
);
impl AbstractEntity for FftwFourierGgswCiphertext64 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for FftwFourierGgswCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;

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

/// A structure representing a GGSW ciphertext with 32 bits of precision in the Fourier domain.
/// Note: The name `FftwFourierGgswCiphertext32` refers to the bit size of the coefficients in the
/// standard domain. Complex coefficients (eg in the Fourier domain) are always represented on 64
/// bits.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwFourierGgswCiphertext32(
    pub(crate) FourierGgswCiphertext<AlignedVec<Complex64>, u32>,
);
impl AbstractEntity for FftwFourierGgswCiphertext32 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for FftwFourierGgswCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;

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
