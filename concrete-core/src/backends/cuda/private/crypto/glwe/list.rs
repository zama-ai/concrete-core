use crate::backends::cuda::private::array::CudaArray;
use crate::commons::numeric::UnsignedInteger;
use crate::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};

/// An array of GLWE ciphertexts in the GPU.
///
/// In the Cuda Engine, the logic is that arrays of GLWE ciphertexts contain
/// arrays of LUT and get copied entirely to all the GPUs.
/// The aim is to make it easy for end users to handle multi-GPU calculations.
/// It is planned to expose an advanced CudaEngine that will make it possible
/// for end users to actually handle GPUs, streams and partitioning on their
/// own.
// Fields with `d_` are data in the GPU
#[derive(Debug)]
pub(crate) struct CudaGlweList<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaArray<T>>,
    // Number of ciphertexts in the array
    pub(crate) glwe_ciphertext_count: GlweCiphertextCount,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
}
