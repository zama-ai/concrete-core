use crate::backends::cuda::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{
    CudaGlweCiphertextVector32, CudaGlweCiphertextVector64,
};
use crate::backends::cuda::private::crypto::glwe::list::CudaGlweList;
use crate::backends::cuda::private::device::GpuIndex;
use crate::backends::cuda::private::pointers::CudaGlweCiphertextVectorPointer;
use crate::commons::crypto::glwe::GlweList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{GlweCiphertextVector32, GlweCiphertextVector64};
use crate::specification::engines::{
    GlweCiphertextVectorConversionEngine, GlweCiphertextVectorConversionError,
};
use crate::specification::entities::GlweCiphertextVectorEntity;

impl From<CudaError> for GlweCiphertextVectorConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 32 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl GlweCiphertextVectorConversionEngine<GlweCiphertextVector32, CudaGlweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 6];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ciphertext_vector);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> Result<CudaGlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> CudaGlweCiphertextVector32 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let d_ptr = stream.malloc::<u32>(data_per_gpu as u32);
            d_ptr_vec.push(CudaGlweCiphertextVectorPointer(d_ptr));
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u32>(d_ptr, input_slice);
        }
        CudaGlweCiphertextVector32(CudaGlweList::<u32> {
            d_ptr_vec,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 32 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextVectorConversionEngine<CudaGlweCiphertextVector32, GlweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 6];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_vector, h_output_ciphertext_vector);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ciphertext_vector);
    /// default_engine.destroy(h_output_ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &CudaGlweCiphertextVector32,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaGlweCiphertextVector32,
    ) -> GlweCiphertextVector32 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u32;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, input.0.get_ptr(GpuIndex(0_u32)).0);
        GlweCiphertextVector32(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl GlweCiphertextVectorConversionEngine<GlweCiphertextVector64, CudaGlweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 6];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ciphertext_vector);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> Result<CudaGlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> CudaGlweCiphertextVector64 {
        // Copy the entire input vector over all GPUs
        let mut d_ptr_vec = Vec::with_capacity(self.get_number_of_gpus() as usize);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = &self.streams[gpu_index];
            let d_ptr = stream.malloc::<u64>(data_per_gpu as u32);
            d_ptr_vec.push(CudaGlweCiphertextVectorPointer(d_ptr));
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u64>(d_ptr, input_slice);
        }
        CudaGlweCiphertextVector64(CudaGlweList::<u64> {
            d_ptr_vec,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextVectorConversionEngine<CudaGlweCiphertextVector64, GlweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 6];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_vector, h_output_ciphertext_vector);
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ciphertext_vector);
    /// default_engine.destroy(h_output_ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &CudaGlweCiphertextVector64,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaGlweCiphertextVector64,
    ) -> GlweCiphertextVector64 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u64;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, input.0.get_ptr(GpuIndex(0_u32)).0);
        GlweCiphertextVector64(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}
