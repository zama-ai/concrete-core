use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::backends::cuda::private::crypto::keyswitch::CudaLweKeyswitchKey;
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::pointers::CudaLweKeyswitchKeyPointer;
use crate::commons::crypto::lwe::LweKeyswitchKey;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{LweKeyswitchKey32, LweKeyswitchKey64};
use crate::specification::engines::{
    LweKeyswitchKeyConversionEngine, LweKeyswitchKeyConversionError,
};
use crate::specification::entities::LweKeyswitchKeyEntity;

impl From<CudaError> for LweKeyswitchKeyConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 32 bits of precision from the CPU to the GPU.
/// We only support the conversion from CPU to GPU: the conversion from GPU to CPU is not
/// necessary at this stage to support the keyswitch. The keyswitch key is copied entirely to all
/// the GPUs.
impl LweKeyswitchKeyConversionEngine<LweKeyswitchKey32, CudaLweKeyswitchKey32> for CudaEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey32 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(ksk)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &LweKeyswitchKey32,
    ) -> Result<CudaLweKeyswitchKey32, LweKeyswitchKeyConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.decomposition_level_count().0
                * (input.output_lwe_dimension().0 + 1)
                * input.input_lwe_dimension().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &LweKeyswitchKey32,
    ) -> CudaLweKeyswitchKey32 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);

        let data_per_gpu = input.decomposition_level_count().0
            * (input.output_lwe_dimension().0 + 1)
            * input.input_lwe_dimension().0;
        let alloc_size = data_per_gpu as u64;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let d_ptr = stream.malloc::<f64>(alloc_size as u32);
            stream.copy_to_gpu(d_ptr, input.0.as_tensor().as_slice());
            d_ptr_vec.push(CudaLweKeyswitchKeyPointer(d_ptr));
        }
        CudaLweKeyswitchKey32(CudaLweKeyswitchKey::<u32> {
            d_ptr_vec,
            input_lwe_dimension: input.input_lwe_dimension(),
            output_lwe_dimension: input.output_lwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 32 bits of precision from the GPU to the CPU.
/// We assume consistency between all the available GPUs and simply copy what is in the one with
/// index 0.
impl LweKeyswitchKeyConversionEngine<CudaLweKeyswitchKey32, LweKeyswitchKey32> for CudaEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey32 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    /// let h_output_ksk: LweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&d_ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    /// assert_eq!(h_output_ksk, h_ksk);
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_output_ksk)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &CudaLweKeyswitchKey32,
    ) -> Result<LweKeyswitchKey32, LweKeyswitchKeyConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLweKeyswitchKey32,
    ) -> LweKeyswitchKey32 {
        let data_per_gpu = input.decomposition_level_count().0
            * (input.output_lwe_dimension().0 + 1)
            * input.input_lwe_dimension().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u32; data_per_gpu];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, input.0.get_ptr(GpuIndex(0)).0);

        LweKeyswitchKey32(LweKeyswitchKey::from_container(
            output,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
            input.output_lwe_dimension(),
        ))
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 64 bits of precision from the CPU to the GPU.
/// We only support the conversion from CPU to GPU: the conversion from GPU to CPU is not
/// necessary at this stage to support the keyswitch. The keyswitch key is copied entirely to all
/// the GPUs.
impl LweKeyswitchKeyConversionEngine<LweKeyswitchKey64, CudaLweKeyswitchKey64> for CudaEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey64 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(ksk)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &LweKeyswitchKey64,
    ) -> Result<CudaLweKeyswitchKey64, LweKeyswitchKeyConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.decomposition_level_count().0
                * (input.output_lwe_dimension().0 + 1)
                * input.input_lwe_dimension().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &LweKeyswitchKey64,
    ) -> CudaLweKeyswitchKey64 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);

        let data_per_gpu = input.decomposition_level_count().0
            * (input.output_lwe_dimension().0 + 1)
            * input.input_lwe_dimension().0;
        let alloc_size = data_per_gpu as u64;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let d_ptr = stream.malloc::<f64>(alloc_size as u32);
            stream.copy_to_gpu(d_ptr, input.0.as_tensor().as_slice());
            d_ptr_vec.push(CudaLweKeyswitchKeyPointer(d_ptr));
        }
        CudaLweKeyswitchKey64(CudaLweKeyswitchKey::<u64> {
            d_ptr_vec,
            input_lwe_dimension: input.input_lwe_dimension(),
            output_lwe_dimension: input.output_lwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
            _phantom: Default::default(),
        })
    }
}

impl LweKeyswitchKeyConversionEngine<CudaLweKeyswitchKey64, LweKeyswitchKey64> for CudaEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::backends::cuda::private::device::GpuIndex;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut default_engine = CoreEngine::new(())?;
    /// let input_key: LweSecretKey64 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    /// let h_output_ksk: LweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&d_ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    /// assert_eq!(h_output_ksk, h_ksk);
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_output_ksk)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &CudaLweKeyswitchKey64,
    ) -> Result<LweKeyswitchKey64, LweKeyswitchKeyConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLweKeyswitchKey64,
    ) -> LweKeyswitchKey64 {
        let data_per_gpu = input.decomposition_level_count().0
            * (input.output_lwe_dimension().0 + 1)
            * input.input_lwe_dimension().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u64; data_per_gpu];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, input.0.get_ptr(GpuIndex(0)).0);

        LweKeyswitchKey64(LweKeyswitchKey::from_container(
            output,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
            input.output_lwe_dimension(),
        ))
    }
}
