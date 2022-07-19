use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::CudaLweCiphertext64;
use crate::commons::math::tensor::AsMutSlice;
use crate::prelude::LweCiphertextMutView64;
use crate::specification::engines::{
    LweCiphertextDiscardingConversionEngine, LweCiphertextDiscardingConversionError,
};

/// # Description
/// Convert an LWE ciphertext with 64 bits of precision from GPU 0 to a view on the CPU.
impl LweCiphertextDiscardingConversionEngine<CudaLweCiphertext64, LweCiphertextMutView64<'_>>
    for CudaEngine
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
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    /// ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext = vec![0_u64; lwe_dimension.0 + 1];
    /// let mut h_view_output_ciphertext: LweCiphertextMutView64 =
    ///     default_engine.create_lwe_ciphertext(h_raw_output_ciphertext.as_mut_slice())?;
    ///
    /// cuda_engine
    ///     .discard_convert_lwe_ciphertext(h_view_output_ciphertext.borrow_mut(), &d_ciphertext)?;
    ///
    /// assert_eq!(h_view_output_ciphertext.lwe_dimension(), lwe_dimension);
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_ciphertext)?;
    /// let h_raw_output_ciphertext: &[u64] =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_view_output_ciphertext)?;
    /// assert_eq!(h_raw_input_ciphertext, h_raw_output_ciphertext.to_vec());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &CudaLweCiphertext64,
    ) -> Result<(), LweCiphertextDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &CudaLweCiphertext64,
    ) {
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(output.0.tensor.as_mut_slice(), &input.0.d_vec);
    }
}
