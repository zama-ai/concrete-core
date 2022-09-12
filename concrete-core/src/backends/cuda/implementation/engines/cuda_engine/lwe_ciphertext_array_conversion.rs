use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{
    CudaLweCiphertextArray32, CudaLweCiphertextArray64,
};
use crate::backends::cuda::private::crypto::lwe::list::{
    copy_lwe_ciphertext_array_from_cpu_to_gpu, copy_lwe_ciphertext_array_from_gpu_to_cpu,
    CudaLweList,
};
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::{compute_number_of_samples_on_gpu, number_of_active_gpus};
use crate::commons::crypto::lwe::LweList;
use crate::prelude::{CiphertextCount, LweCiphertextArray32, LweCiphertextArray64};
use crate::specification::engines::{
    LweCiphertextArrayConversionEngine, LweCiphertextArrayConversionError,
};
use crate::specification::entities::LweCiphertextArrayEntity;

impl From<CudaError> for LweCiphertextArrayConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext array with 32 bits of precision from CPU to GPU.
///
/// The input ciphertext array is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextArrayConversionEngine<LweCiphertextArray32, CudaLweCiphertextArray32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray32 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray32 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> Result<CudaLweCiphertextArray32, LweCiphertextArrayConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> CudaLweCiphertextArray32 {
        let vecs = copy_lwe_ciphertext_array_from_cpu_to_gpu::<u32, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextArray32(CudaLweList::<u32> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext array with 32 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextArray32 on the CPU.
impl LweCiphertextArrayConversionEngine<CudaLweCiphertextArray32, LweCiphertextArray32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray32 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray32 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// let h_ciphertext_array_output: LweCiphertextArray32 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&d_ciphertext_array)?;
    /// assert_eq!(h_ciphertext_array_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_array_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_array, h_ciphertext_array_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &CudaLweCiphertextArray32,
    ) -> Result<LweCiphertextArray32, LweCiphertextArrayConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &CudaLweCiphertextArray32,
    ) -> LweCiphertextArray32 {
        let output = copy_lwe_ciphertext_array_from_gpu_to_cpu::<u32>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        LweCiphertextArray32(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}

/// # Description
/// Convert an LWE ciphertext array with 64 bits of precision from CPU to GPU.
///
/// The input ciphertext array is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextArrayConversionEngine<LweCiphertextArray64, CudaLweCiphertextArray64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_array: PlaintextArray64 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray64 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray64 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &LweCiphertextArray64,
    ) -> Result<CudaLweCiphertextArray64, LweCiphertextArrayConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &LweCiphertextArray64,
    ) -> CudaLweCiphertextArray64 {
        let vecs = copy_lwe_ciphertext_array_from_cpu_to_gpu::<u64, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextArray64(CudaLweList::<u64> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext array with 64 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextArray64 on the CPU.
impl LweCiphertextArrayConversionEngine<CudaLweCiphertextArray64, LweCiphertextArray64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_array: PlaintextArray64 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray64 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray64 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// let h_ciphertext_array_output: LweCiphertextArray64 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&d_ciphertext_array)?;
    /// assert_eq!(h_ciphertext_array_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_array_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_array, h_ciphertext_array_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &CudaLweCiphertextArray64,
    ) -> Result<LweCiphertextArray64, LweCiphertextArrayConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &CudaLweCiphertextArray64,
    ) -> LweCiphertextArray64 {
        let output = copy_lwe_ciphertext_array_from_gpu_to_cpu::<u64>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        LweCiphertextArray64(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}
