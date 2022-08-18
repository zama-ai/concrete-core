//! Keyswitch key with Cuda.
use crate::backends::cuda::private::vec::CudaVec;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

#[derive(Debug)]
pub(crate) struct CudaLweKeyswitchKey<T: UnsignedInteger> {
    // Pointers to GPU data: one cuda vec per GPU
    pub(crate) d_vecs: Vec<CudaVec<T>>,
    // Input LWE dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Output LWE dimension
    pub(crate) output_lwe_dimension: LweDimension,
    // Number of decomposition levels
    pub(crate) decomp_level: DecompositionLevelCount,
    // Value of the base log for the decomposition
    pub(crate) decomp_base_log: DecompositionBaseLog,
}
