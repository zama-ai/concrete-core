use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    CleartextArray32, CleartextArray64, LweCiphertext32, LweCiphertext64, LweCiphertextArray32,
    LweCiphertextArray64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextArrayDiscardingAffineTransformationEngine,
    LweCiphertextArrayDiscardingAffineTransformationError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingAffineTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCiphertextArrayDiscardingAffineTransformationEngine<
        LweCiphertextArray32,
        CleartextArray32,
        Plaintext32,
        LweCiphertext32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_array = vec![3_u32 << 20; 8];
    /// let weights_input = vec![2_u32; 8];
    /// let bias_input = 8_u32 << 20;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextArray32 = engine.create_cleartext_array_from(&input_array)?;
    /// let bias: Plaintext32 = engine.create_plaintext_from(&bias_input)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array = engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_affine_transform_lwe_ciphertext_array(
    ///     &mut output_ciphertext,
    ///     &ciphertext_array,
    ///     &weights,
    ///     &bias,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_affine_transform_lwe_ciphertext_array(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextArray32,
        weights: &CleartextArray32,
        bias: &Plaintext32,
    ) -> Result<(), LweCiphertextArrayDiscardingAffineTransformationError<Self::EngineError>> {
        LweCiphertextArrayDiscardingAffineTransformationError::perform_generic_checks(
            output, inputs, weights,
        )?;
        unsafe {
            self.discard_affine_transform_lwe_ciphertext_array_unchecked(
                output, inputs, weights, bias,
            )
        };
        Ok(())
    }

    unsafe fn discard_affine_transform_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextArray32,
        weights: &CleartextArray32,
        bias: &Plaintext32,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingAffineTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCiphertextArrayDiscardingAffineTransformationEngine<
        LweCiphertextArray64,
        CleartextArray64,
        Plaintext64,
        LweCiphertext64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_array = vec![3_u64 << 50; 8];
    /// let weights_input = vec![2_u64; 8];
    /// let bias_input = 8_u64 << 50;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextArray64 = engine.create_cleartext_array_from(&input_array)?;
    /// let bias: Plaintext64 = engine.create_plaintext_from(&bias_input)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array = engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    ///
    /// engine.discard_affine_transform_lwe_ciphertext_array(
    ///     &mut output_ciphertext,
    ///     &ciphertext_array,
    ///     &weights,
    ///     &bias,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_affine_transform_lwe_ciphertext_array(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextArray64,
        weights: &CleartextArray64,
        bias: &Plaintext64,
    ) -> Result<(), LweCiphertextArrayDiscardingAffineTransformationError<Self::EngineError>> {
        LweCiphertextArrayDiscardingAffineTransformationError::perform_generic_checks(
            output, inputs, weights,
        )?;
        unsafe {
            self.discard_affine_transform_lwe_ciphertext_array_unchecked(
                output, inputs, weights, bias,
            )
        };
        Ok(())
    }

    unsafe fn discard_affine_transform_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextArray64,
        weights: &CleartextArray64,
        bias: &Plaintext64,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}
