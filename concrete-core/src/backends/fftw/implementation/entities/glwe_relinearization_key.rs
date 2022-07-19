use crate::backends::fftw::private::crypto::glwe::{GlweRelinearizationKey};
use crate::specification::entities::markers::{
    BinaryKeyDistribution, GlweRelinearizationKeyKind,
};
use crate::specification::entities::{AbstractEntity, GlweRelinearizationKeyEntity};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;

/// A structure representing a GLWE relinearization key with 32 bits of precision in the standard
/// domain.
#[derive(Debug, Clone, PartialEq)]
pub struct FftwStandardGlweRelinearizationKey32(
    pub(crate) StandardGlweRelinearizationKey<Vec<u32>>,
);
impl AbstractEntity for FftwStandardGlweRelinearizationKey32 {
    type Kind = GlweRelinearizationKeyKind;
}
impl GlweRelinearizationKeyEntity for FftwStandardGlweRelinearizationKey32 {
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

/// A structure representing a GLWE relinearization key with 64 bits of precision in the standard
/// domain. 
#[derive(Debug, Clone, PartialEq)]
pub struct FftwStandardGlweRelinearizationKey64(
    pub(crate) StandardGlweRelinearizationKey<Vec<u64>>,
);
impl AbstractEntity for FftwStandardGlweRelinearizationKey64 {
    type Kind = GlweRelinearizationKeyKind;
}
impl GlweRelinearizationKeyEntity for FftwStandardGlweRelinearizationKey64 {
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
