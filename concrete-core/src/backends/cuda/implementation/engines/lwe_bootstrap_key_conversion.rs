use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64,
};
use crate::backends::cuda::private::crypto::bootstrap::CudaBootstrapKey;
use crate::backends::cuda::private::pointers::CudaBootstrapKeyPointer;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{LweBootstrapKey32, LweBootstrapKey64};
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;
use std::ffi::c_void;

impl From<CudaError> for LweBootstrapKeyConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE bootstrap key corresponding to 32 bits of precision from the CPU to the GPU.
/// The bootstrap key is copied entirely to all the GPUs and converted from the standard to the
/// Fourier domain.

impl LweBootstrapKeyConversionEngine<LweBootstrapKey32, CudaFourierLweBootstrapKey32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey32 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// assert_eq!(d_fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(d_fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(d_fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(d_fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(d_fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// cuda_engine.destroy(d_fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> Result<CudaFourierLweBootstrapKey32, LweBootstrapKeyConversionError<CudaError>> {
        let poly_size = input.0.polynomial_size().0;
        check_poly_size!(poly_size);
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_dimension().to_glwe_size().0
                * input.input_lwe_dimension().0
                * input.decomposition_level_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> CudaFourierLweBootstrapKey32 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);
        // TODO
        //   Check if it would be better to have GPU 0 compute the BSK and copy it back to the
        //   CPU, then copy the BSK to the other GPUs. Are we sure the BSK generated on each GPU
        //   will be exactly the same?
        let total_polynomials = input.input_lwe_dimension().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let alloc_size = total_polynomials * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            stream.initialize_twiddles(input.polynomial_size().0 as u32);
            let d_ptr = stream.malloc::<f64>(alloc_size as u32);
            d_ptr_vec.push(CudaBootstrapKeyPointer(d_ptr));

            let input_ptr = input.0.as_tensor().as_slice();
            stream.convert_lwe_bootstrap_key_32(
                d_ptr,
                input_ptr.as_ptr() as *mut c_void,
                input.input_lwe_dimension().0 as u32,
                input.glwe_dimension().0 as u32,
                input.decomposition_level_count().0 as u32,
                input.polynomial_size().0 as u32,
            );
        }
        CudaFourierLweBootstrapKey32(CudaBootstrapKey::<u32> {
            d_ptr_vec,
            polynomial_size: input.polynomial_size(),
            input_lwe_dimension: input.input_lwe_dimension(),
            glwe_dimension: input.glwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE bootstrap key corresponding to 64 bits of precision from the CPU to the GPU.
/// The bootstrap key is copied entirely to all the GPUs and converted from the standard to the
/// Fourier domain.

impl LweBootstrapKeyConversionEngine<LweBootstrapKey64, CudaFourierLweBootstrapKey64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey64 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// assert_eq!(d_fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(d_fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(d_fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(d_fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(d_fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// cuda_engine.destroy(d_fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> Result<CudaFourierLweBootstrapKey64, LweBootstrapKeyConversionError<CudaError>> {
        let poly_size = input.0.polynomial_size().0;
        check_poly_size!(poly_size);
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_dimension().to_glwe_size().0
                * input.input_lwe_dimension().0
                * input.decomposition_level_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> CudaFourierLweBootstrapKey64 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);
        // TODO
        //   Check if it would be better to have GPU 0 compute the BSK and copy it back to the
        //   CPU, then copy the BSK to the other GPUs. Are we sure the BSK generated on each GPU
        //   will be exactly the same?
        let total_polynomials = input.input_lwe_dimension().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;

        let alloc_size = total_polynomials * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            stream.initialize_twiddles(input.polynomial_size().0 as u32);
            let d_ptr = stream.malloc::<f64>(alloc_size as u32);
            d_ptr_vec.push(CudaBootstrapKeyPointer(d_ptr));

            let input_ptr = input.0.as_tensor().as_slice();
            stream.convert_lwe_bootstrap_key_64(
                d_ptr,
                input_ptr.as_ptr() as *mut c_void,
                input.input_lwe_dimension().0 as u32,
                input.glwe_dimension().0 as u32,
                input.decomposition_level_count().0 as u32,
                input.polynomial_size().0 as u32,
            );
        }
        CudaFourierLweBootstrapKey64(CudaBootstrapKey::<u64> {
            d_ptr_vec,
            polynomial_size: input.polynomial_size(),
            input_lwe_dimension: input.input_lwe_dimension(),
            glwe_dimension: input.glwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
            _phantom: Default::default(),
        })
    }
}
