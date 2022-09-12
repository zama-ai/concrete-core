use crate::backends::cuda::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::{
    CudaGlweCiphertextArray32, CudaGlweCiphertextArray64,
};
use crate::backends::cuda::private::crypto::glwe::list::CudaGlweList;
use crate::commons::crypto::glwe::GlweList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::prelude::{GlweCiphertextArray32, GlweCiphertextArray64};
use crate::specification::engines::{
    GlweCiphertextArrayConversionEngine, GlweCiphertextArrayConversionError,
};
use crate::specification::entities::GlweCiphertextArrayEntity;

impl From<CudaError> for GlweCiphertextArrayConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GLWE ciphertext array with 32 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole array of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input array of lookup tables for the bootstrap.
impl GlweCiphertextArrayConversionEngine<GlweCiphertextArray32, CudaGlweCiphertextArray32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: GlweCiphertextArray32 =
    ///     default_engine.encrypt_glwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaGlweCiphertextArray32 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_array.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_array(
        &mut self,
        input: &GlweCiphertextArray32,
    ) -> Result<CudaGlweCiphertextArray32, GlweCiphertextArrayConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &GlweCiphertextArray32,
    ) -> CudaGlweCiphertextArray32 {
        // Copy the entire input array over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u32>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextArray32(CudaGlweList::<u32> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext array with 32 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextArrayConversionEngine<CudaGlweCiphertextArray32, GlweCiphertextArray32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: GlweCiphertextArray32 =
    ///     default_engine.encrypt_glwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaGlweCiphertextArray32 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&h_ciphertext_array)?;
    /// let h_output_ciphertext_array: GlweCiphertextArray32 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&d_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_array, h_output_ciphertext_array);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_array(
        &mut self,
        input: &CudaGlweCiphertextArray32,
    ) -> Result<GlweCiphertextArray32, GlweCiphertextArrayConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &CudaGlweCiphertextArray32,
    ) -> GlweCiphertextArray32 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u32;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, input.0.d_vecs.first().unwrap());
        GlweCiphertextArray32(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a GLWE ciphertext array with 64 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole array of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input array of lookup tables for the bootstrap.
impl GlweCiphertextArrayConversionEngine<GlweCiphertextArray64, CudaGlweCiphertextArray64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_array: PlaintextArray64 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: GlweCiphertextArray64 =
    ///     default_engine.encrypt_glwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaGlweCiphertextArray64 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&h_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_array.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_array(
        &mut self,
        input: &GlweCiphertextArray64,
    ) -> Result<CudaGlweCiphertextArray64, GlweCiphertextArrayConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &GlweCiphertextArray64,
    ) -> CudaGlweCiphertextArray64 {
        // Copy the entire input array over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u64>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextArray64(CudaGlweList::<u64> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext array with 64 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextArrayConversionEngine<CudaGlweCiphertextArray64, GlweCiphertextArray64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_array: PlaintextArray64 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: GlweCiphertextArray64 =
    ///     default_engine.encrypt_glwe_ciphertext_array(&h_key, &h_plaintext_array, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaGlweCiphertextArray64 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&h_ciphertext_array)?;
    /// let h_output_ciphertext_array: GlweCiphertextArray64 =
    ///     cuda_engine.convert_glwe_ciphertext_array(&d_ciphertext_array)?;
    ///
    /// assert_eq!(d_ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_array.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(d_ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_array, h_output_ciphertext_array);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_array(
        &mut self,
        input: &CudaGlweCiphertextArray64,
    ) -> Result<GlweCiphertextArray64, GlweCiphertextArrayConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &CudaGlweCiphertextArray64,
    ) -> GlweCiphertextArray64 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u64;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, input.0.d_vecs.first().unwrap());
        GlweCiphertextArray64(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}
