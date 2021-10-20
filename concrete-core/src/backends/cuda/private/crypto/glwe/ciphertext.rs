use std::marker::PhantomData;

use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

use crate::backends::cuda::private::pointers::CudaGlweCiphertextPointer;

/// One GLWE ciphertext on GPU 0.
///
/// There is no multi GPU support at this stage since the user cannot
/// specify on which GPU to convert the data.
// Fields with `d_` are data in the GPU
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaGlweCiphertext<T: UnsignedInteger> {
    // Pointer to GPU data: one pointer on GPU 0
    pub(crate) d_ptr: CudaGlweCiphertextPointer,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaGlweCiphertext<T> {
    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Returns a pointer to the data on a chosen GPU
    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self) -> CudaGlweCiphertextPointer {
        self.d_ptr
    }
}
