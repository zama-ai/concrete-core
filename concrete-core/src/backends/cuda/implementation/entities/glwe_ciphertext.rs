use std::fmt::Debug;

use concrete_commons::parameters::{GlweDimension, PolynomialSize};

use crate::backends::cuda::private::crypto::glwe::ciphertext::CudaGlweCiphertext;
use crate::specification::entities::markers::{BinaryKeyDistribution, GlweCiphertextKind};
use crate::specification::entities::{AbstractEntity, GlweCiphertextEntity};

/// A structure representing a vector of GLWE ciphertexts with 32 bits of precision on the GPU.
/// It is used as input to the Cuda bootstrap for the array of lookup tables.
#[derive(Debug, PartialEq, Eq)]
pub struct CudaGlweCiphertext32(pub(crate) CudaGlweCiphertext<u32>);

impl AbstractEntity for CudaGlweCiphertext32 {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for CudaGlweCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
/// It is used as input to the Cuda bootstrap for the array of lookup tables.
#[derive(Debug, PartialEq, Eq)]
pub struct CudaGlweCiphertext64(pub(crate) CudaGlweCiphertext<u64>);

impl AbstractEntity for CudaGlweCiphertext64 {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for CudaGlweCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
