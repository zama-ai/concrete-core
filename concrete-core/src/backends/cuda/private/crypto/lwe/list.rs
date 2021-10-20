use std::marker::PhantomData;

use crate::backends::cuda::private::device::GpuIndex;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};

use crate::backends::cuda::private::pointers::CudaLweCiphertextVectorPointer;

/// An array of LWE ciphertexts in the GPU.
///
/// In the Cuda Engine, the logic is that vectors of LWE ciphertexts get
/// chunked and each chunk is sent to a given GPU.
/// The amount of ciphertexts per GPU is hard set to the total amount of
/// ciphertexts divided by the number of GPUs.
/// The aim is to make it easy for end users to handle multi-GPU calculations.
/// It is planned to expose an advanced CudaEngine that will make it possible
/// for end users to actually handle GPUs, streams and partitioning on their
/// own.
/// FIXME: the last GPU is less charged because it only takes the
///   remainder of the division of the total amount of input ciphertexts
///   by the number of GPUs. Originally, we were thinking of giving the
///   last GPU the same amount of ciphertexts as the others + the ciphertexts
///   that don't fit in case the remainder is not zero.

// Fields with `d_` are data in the GPU
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaLweList<T: UnsignedInteger> {
    // Pointers to GPU data: one pointer per GPU
    pub(crate) d_ptr_vec: Vec<CudaLweCiphertextVectorPointer>,
    // Number of ciphertexts in the array
    pub(crate) lwe_ciphertext_count: LweCiphertextCount,
    // Lwe dimension
    pub(crate) lwe_dimension: LweDimension,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaLweList<T> {
    pub(crate) fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.lwe_ciphertext_count
    }

    pub(crate) fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Returns a mut pointer to the GPU data on a chosen GPU
    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self, gpu_index: GpuIndex) -> CudaLweCiphertextVectorPointer {
        self.d_ptr_vec[gpu_index.0 as usize]
    }
}
