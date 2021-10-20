//! Bootstrap key with Cuda.
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::pointers::CudaBootstrapKeyPointer;
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CudaBootstrapKey<T: UnsignedInteger> {
    // Pointers to GPU data: one pointer per GPU
    pub(crate) d_ptr_vec: Vec<CudaBootstrapKeyPointer>,
    // Input LWE dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Size of polynomials in the key
    pub(crate) polynomial_size: PolynomialSize,
    // GLWE dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Number of decomposition levels
    pub(crate) decomp_level: DecompositionLevelCount,
    // Value of the base log for the decomposition
    pub(crate) decomp_base_log: DecompositionBaseLog,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: UnsignedInteger> CudaBootstrapKey<T> {
    #[allow(dead_code)]
    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    #[allow(dead_code)]
    pub(crate) fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    #[allow(dead_code)]
    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
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
    pub(crate) unsafe fn get_ptr(&self, gpu_index: GpuIndex) -> CudaBootstrapKeyPointer {
        self.d_ptr_vec[gpu_index.0 as usize]
    }
}
