//! Keyswitch key with Cuda.
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::pointers::CudaLweKeyswitchKeyPointer;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaLweKeyswitchKey<T: UnsignedInteger> {
    // Pointers to GPU data: one pointer per GPU
    pub(crate) d_ptr_vec: Vec<CudaLweKeyswitchKeyPointer>,
    // Input LWE dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Output LWE dimension
    pub(crate) output_lwe_dimension: LweDimension,
    // Number of decomposition levels
    pub(crate) decomp_level: DecompositionLevelCount,
    // Value of the base log for the decomposition
    pub(crate) decomp_base_log: DecompositionBaseLog,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaLweKeyswitchKey<T> {
    #[allow(dead_code)]
    pub(crate) fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    #[allow(dead_code)]
    pub(crate) fn output_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_dimension
    }

    #[allow(dead_code)]
    pub(crate) fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level
    }

    #[allow(dead_code)]
    pub(crate) fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self, gpu_index: GpuIndex) -> CudaLweKeyswitchKeyPointer {
        self.d_ptr_vec[gpu_index.0 as usize]
    }
}
