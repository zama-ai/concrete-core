use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaLweCiphertextArray32, CudaLweCiphertextArray64, CudaLweKeyswitchKey32,
    CudaLweKeyswitchKey64,
};
use crate::backends::cuda::private::crypto::keyswitch::execute_lwe_ciphertext_array_keyswitch_on_gpu;
use crate::specification::engines::{
    LweCiphertextArrayDiscardingKeyswitchEngine, LweCiphertextArrayDiscardingKeyswitchError,
};

impl From<CudaError> for LweCiphertextArrayDiscardingKeyswitchError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard keyswitch on an array of input ciphertext arrays with 32 bits of precision.
impl
    LweCiphertextArrayDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey32,
        CudaLweCiphertextArray32,
        CudaLweCiphertextArray32,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let input_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray32 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&input_key, &h_plaintext_array, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray32 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext_array: LweCiphertextArray32 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_array(
    ///         &h_dummy_key,
    ///         noise,
    ///         h_ciphertext_array.lwe_ciphertext_count(),
    ///     )?;
    ///
    /// let mut d_keyswitched_ciphertext_array: CudaLweCiphertextArray32 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_zero_ciphertext_array)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext_array(
    ///     &mut d_keyswitched_ciphertext_array,
    ///     &d_ciphertext_array,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_array.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_array.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut CudaLweCiphertextArray32,
        input: &CudaLweCiphertextArray32,
        ksk: &CudaLweKeyswitchKey32,
    ) -> Result<(), LweCiphertextArrayDiscardingKeyswitchError<CudaError>> {
        LweCiphertextArrayDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_array_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextArray32,
        input: &CudaLweCiphertextArray32,
        ksk: &CudaLweKeyswitchKey32,
    ) {
        execute_lwe_ciphertext_array_keyswitch_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &ksk.0,
            self.get_number_of_gpus(),
        );
    }
}

/// # Description
/// A discard keyswitch on an array of input ciphertext arrays with 64 bits of precision.
impl
    LweCiphertextArrayDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey64,
        CudaLweCiphertextArray64,
        CudaLweCiphertextArray64,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let input_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext_array: PlaintextArray64 = default_engine.create_plaintext_array_from(&input)?;
    /// let mut h_ciphertext_array: LweCiphertextArray64 =
    ///     default_engine.encrypt_lwe_ciphertext_array(&input_key, &h_plaintext_array, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_array: CudaLweCiphertextArray64 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_ciphertext_array)?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext_array: LweCiphertextArray64 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_array(
    ///         &h_dummy_key,
    ///         noise,
    ///         h_ciphertext_array.lwe_ciphertext_count(),
    ///     )?;
    ///
    /// let mut d_keyswitched_ciphertext_array: CudaLweCiphertextArray64 =
    ///     cuda_engine.convert_lwe_ciphertext_array(&h_zero_ciphertext_array)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext_array(
    ///     &mut d_keyswitched_ciphertext_array,
    ///     &d_ciphertext_array,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_array.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    /// assert_eq!(
    ///     d_keyswitched_ciphertext_array.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext_array(
        &mut self,
        output: &mut CudaLweCiphertextArray64,
        input: &CudaLweCiphertextArray64,
        ksk: &CudaLweKeyswitchKey64,
    ) -> Result<(), LweCiphertextArrayDiscardingKeyswitchError<CudaError>> {
        LweCiphertextArrayDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_array_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextArray64,
        input: &CudaLweCiphertextArray64,
        ksk: &CudaLweKeyswitchKey64,
    ) {
        execute_lwe_ciphertext_array_keyswitch_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &ksk.0,
            self.get_number_of_gpus(),
        );
    }
}
