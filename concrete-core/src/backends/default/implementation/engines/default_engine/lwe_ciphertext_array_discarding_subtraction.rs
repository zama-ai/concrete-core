use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray32, LweCiphertextArray64,
};
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::specification::engines::{
    LweCiphertextArrayDiscardingSubtractionEngine, LweCiphertextArrayDiscardingSubtractionError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingSubtractionEngine`] for [`DefaultEngine`]
/// that operates on 32 bits integers.
impl LweCiphertextArrayDiscardingSubtractionEngine<LweCiphertextArray32, LweCiphertextArray32>
    for DefaultEngine
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
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array = engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    /// let mut output_ciphertext_array =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext_array(
    ///     &mut output_ciphertext_array,
    ///     &ciphertext_array,
    ///     &ciphertext_array,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext_array.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext_array(
        &mut self,
        output: &mut LweCiphertextArray32,
        input_1: &LweCiphertextArray32,
        input_2: &LweCiphertextArray32,
    ) -> Result<(), LweCiphertextArrayDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingSubtractionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_sub_lwe_ciphertext_array_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut LweCiphertextArray32,
        input_1: &LweCiphertextArray32,
        input_2: &LweCiphertextArray32,
    ) {
        for (mut out, (in_1, in_2)) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter().zip(input_2.0.ciphertext_iter()))
        {
            out.as_mut_tensor().fill_with_copy(in_1.as_tensor());
            out.update_with_sub(&in_2);
        }
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingSubtractionEngine`] for [`DefaultEngine`]
/// that operates on 64 bits integers.
impl LweCiphertextArrayDiscardingSubtractionEngine<LweCiphertextArray64, LweCiphertextArray64>
    for DefaultEngine
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
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input_array)?;
    /// let ciphertext_array = engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    /// let mut output_ciphertext_array =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_sub_lwe_ciphertext_array(
    ///     &mut output_ciphertext_array,
    ///     &ciphertext_array,
    ///     &ciphertext_array,
    /// )?;
    /// #
    /// assert_eq!(output_ciphertext_array.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_sub_lwe_ciphertext_array(
        &mut self,
        output: &mut LweCiphertextArray64,
        input_1: &LweCiphertextArray64,
        input_2: &LweCiphertextArray64,
    ) -> Result<(), LweCiphertextArrayDiscardingSubtractionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingSubtractionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_sub_lwe_ciphertext_array_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_sub_lwe_ciphertext_array_unchecked(
        &mut self,
        output: &mut LweCiphertextArray64,
        input_1: &LweCiphertextArray64,
        input_2: &LweCiphertextArray64,
    ) {
        for (mut out, (in_1, in_2)) in output
            .0
            .ciphertext_iter_mut()
            .zip(input_1.0.ciphertext_iter().zip(input_2.0.ciphertext_iter()))
        {
            out.as_mut_tensor().fill_with_copy(in_1.as_tensor());
            out.update_with_sub(&in_2);
        }
    }
}
