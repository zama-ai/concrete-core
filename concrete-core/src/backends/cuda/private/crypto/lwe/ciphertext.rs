use std::marker::PhantomData;

use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::LweDimension;

use crate::backends::cuda::private::pointers::CudaLweCiphertextPointer;

/// An LWE ciphertext on the GPU 0.
///
/// There is no multi GPU support at this stage since the user cannot
/// specify on which GPU to convert the data.

// Fields with `d_` are data in the GPU
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaLweCiphertext<T: UnsignedInteger> {
    // Pointers to GPU data: one pointer per GPU
    pub(crate) d_ptr: CudaLweCiphertextPointer,
    // Lwe dimension
    pub(crate) lwe_dimension: LweDimension,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaLweCiphertext<T> {
    pub(crate) fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Returns a mut pointer to the GPU data on GPU 0
    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self) -> CudaLweCiphertextPointer {
        self.d_ptr
    }
}
