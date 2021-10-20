use std::marker::PhantomData;

use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};

use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::pointers::CudaGlweCiphertextVectorPointer;

/// An array of GLWE ciphertexts in the GPU.
///
/// In the Cuda Engine, the logic is that vectors of GLWE ciphertexts contain
/// vectors of LUT and get copied entirely to all the GPUs.
/// The aim is to make it easy for end users to handle multi-GPU calculations.
/// It is planned to expose an advanced CudaEngine that will make it possible
/// for end users to actually handle GPUs, streams and partitioning on their
/// own.
// Fields with `d_` are data in the GPU
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaGlweList<T: UnsignedInteger> {
    // Pointers to GPU data: one pointer per GPU
    pub(crate) d_ptr_vec: Vec<CudaGlweCiphertextVectorPointer>,
    // Number of ciphertexts in the array
    pub(crate) glwe_ciphertext_count: GlweCiphertextCount,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaGlweList<T> {
    pub(crate) fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        self.glwe_ciphertext_count
    }

    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Returns a pointer to the data on a chosen GPU
    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self, gpu_index: GpuIndex) -> CudaGlweCiphertextVectorPointer {
        self.d_ptr_vec[gpu_index.0 as usize]
    }
}
