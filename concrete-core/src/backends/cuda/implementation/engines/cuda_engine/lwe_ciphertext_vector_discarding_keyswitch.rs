use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaLweCiphertextVector32, CudaLweCiphertextVector64, CudaLweKeyswitchKey32,
    CudaLweKeyswitchKey64,
};
use crate::backends::cuda::private::device::NumberOfSamples;
use crate::specification::engines::{
    LweCiphertextVectorDiscardingKeyswitchEngine, LweCiphertextVectorDiscardingKeyswitchError,
};

impl From<CudaError> for LweCiphertextVectorDiscardingKeyswitchError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 32 bits of precision.
impl
    LweCiphertextVectorDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey32,
        CudaLweCiphertextVector32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    ///
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Generate two secret keys
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext_vector: PlaintextVector32 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&input_key, &h_plaintext_vector, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey32 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext_vector: LweCiphertextVector32 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_vector(
    ///         &h_dummy_key,
    ///         noise,
    ///         h_ciphertext_vector.lwe_ciphertext_count(),
    ///     )?;
    ///
    /// let mut d_keyswitched_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_zero_ciphertext_vector)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext_vector(
    ///     &mut d_keyswitched_ciphertext_vector,
    ///     &d_ciphertext_vector,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_vector.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// default_engine.destroy(h_zero_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// cuda_engine.destroy(d_ciphertext_vector)?;
    /// cuda_engine.destroy(d_keyswitched_ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
        ksk: &CudaLweKeyswitchKey32,
    ) -> Result<(), LweCiphertextVectorDiscardingKeyswitchError<CudaError>> {
        LweCiphertextVectorDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_vector_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
        ksk: &CudaLweKeyswitchKey32,
    ) {
        let samples_per_gpu =
            NumberOfSamples(input.0.lwe_ciphertext_count().0 / self.get_number_of_gpus());

        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = self.streams.get(gpu_index).unwrap();

            stream.discard_keyswitch_lwe_ciphertext_vector_32(
                output.0.d_vecs.get_mut(gpu_index).unwrap(),
                input.0.d_vecs.get(gpu_index).unwrap(),
                input.0.lwe_dimension,
                output.0.lwe_dimension,
                ksk.0.d_vecs.get(gpu_index).unwrap(),
                ksk.0.decomposition_base_log(),
                ksk.0.decomposition_level_count(),
                samples_per_gpu,
            );
        }
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 64 bits of precision.
impl
    LweCiphertextVectorDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey64,
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    ///
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Generate two secret keys
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = default_engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext_vector: PlaintextVector64 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&input_key, &h_plaintext_vector, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey64 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext_vector: LweCiphertextVector64 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_vector(
    ///         &h_dummy_key,
    ///         noise,
    ///         h_ciphertext_vector.lwe_ciphertext_count(),
    ///     )?;
    ///
    /// let mut d_keyswitched_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_zero_ciphertext_vector)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext_vector(
    ///     &mut d_keyswitched_ciphertext_vector,
    ///     &d_ciphertext_vector,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_vector.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// default_engine.destroy(h_ciphertext_vector)?;
    /// default_engine.destroy(h_zero_ciphertext_vector)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// cuda_engine.destroy(d_ciphertext_vector)?;
    /// cuda_engine.destroy(d_keyswitched_ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        ksk: &CudaLweKeyswitchKey64,
    ) -> Result<(), LweCiphertextVectorDiscardingKeyswitchError<CudaError>> {
        LweCiphertextVectorDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_vector_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        ksk: &CudaLweKeyswitchKey64,
    ) {
        let samples_per_gpu =
            NumberOfSamples(input.0.lwe_ciphertext_count().0 / self.get_number_of_gpus());

        for gpu_index in 0..self.get_number_of_gpus() {
            let stream = self.streams.get(gpu_index).unwrap();

            stream.discard_keyswitch_lwe_ciphertext_vector_64(
                output.0.d_vecs.get_mut(gpu_index).unwrap(),
                input.0.d_vecs.get(gpu_index).unwrap(),
                input.0.lwe_dimension,
                output.0.lwe_dimension,
                ksk.0.d_vecs.get(gpu_index).unwrap(),
                ksk.0.decomposition_base_log(),
                ksk.0.decomposition_level_count(),
                samples_per_gpu,
            );
        }
    }
}
