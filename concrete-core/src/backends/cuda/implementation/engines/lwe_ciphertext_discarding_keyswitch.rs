use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaLweCiphertext32, CudaLweCiphertext64, CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::backends::cuda::private::device::GpuIndex;
use crate::specification::engines::{
    LweCiphertextDiscardingKeyswitchEngine, LweCiphertextDiscardingKeyswitchError,
};
use crate::specification::entities::LweCiphertextEntity;

impl From<CudaError> for LweCiphertextDiscardingKeyswitchError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 32 bits of precision.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey32,
        CudaLweCiphertext32,
        CudaLweCiphertext32,
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
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Generate two secret keys
    /// let mut default_engine = CoreEngine::new(())?;
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
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&input_key, &h_plaintext, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey32 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext: LweCiphertext32 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    ///
    /// let mut d_keyswitched_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_ciphertext)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext(
    ///     &mut d_keyswitched_ciphertext,
    ///     &d_ciphertext,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// default_engine.destroy(h_zero_ciphertext)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// cuda_engine.destroy(d_ciphertext)?;
    /// cuda_engine.destroy(d_keyswitched_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        ksk: &CudaLweKeyswitchKey32,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<CudaError>> {
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        ksk: &CudaLweKeyswitchKey32,
    ) {
        let stream = &self.streams[0];

        stream.discard_keyswitch_lwe_ciphertext_vector_32(
            output.0.get_ptr().0,
            input.0.get_ptr().0,
            input.lwe_dimension().0 as u32,
            output.lwe_dimension().0 as u32,
            ksk.0.get_ptr(GpuIndex(0)).0,
            ksk.0.decomposition_base_log().0 as u32,
            ksk.0.decomposition_level_count().0 as u32,
            1,
        );
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 64 bits of precision.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey64,
        CudaLweCiphertext64,
        CudaLweCiphertext64,
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
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Generate two secret keys
    /// let mut default_engine = CoreEngine::new(())?;
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
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&input_key, &h_plaintext, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey64 = default_engine.create_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext: LweCiphertext64 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    ///
    /// let mut d_keyswitched_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_ciphertext)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext(
    ///     &mut d_keyswitched_ciphertext,
    ///     &d_ciphertext,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    ///
    /// default_engine.destroy(input_key)?;
    /// default_engine.destroy(output_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_ksk)?;
    /// default_engine.destroy(h_plaintext)?;
    /// default_engine.destroy(h_ciphertext)?;
    /// default_engine.destroy(h_zero_ciphertext)?;
    /// cuda_engine.destroy(d_ksk)?;
    /// cuda_engine.destroy(d_ciphertext)?;
    /// cuda_engine.destroy(d_keyswitched_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        ksk: &CudaLweKeyswitchKey64,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<CudaError>> {
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        ksk: &CudaLweKeyswitchKey64,
    ) {
        let stream = &self.streams[0];

        stream.discard_keyswitch_lwe_ciphertext_vector_64(
            output.0.get_ptr().0,
            input.0.get_ptr().0,
            input.lwe_dimension().0 as u32,
            output.lwe_dimension().0 as u32,
            ksk.0.get_ptr(GpuIndex(0)).0,
            ksk.0.decomposition_base_log().0 as u32,
            ksk.0.decomposition_level_count().0 as u32,
            1,
        );
    }
}
