use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray32, LweCiphertextArray64, LweSecretKey32, LweSecretKey64, PlaintextArray32,
    PlaintextArray64,
};
use crate::specification::engines::{
    LweCiphertextArrayDiscardingDecryptionEngine, LweCiphertextArrayDiscardingDecryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextArrayDiscardingDecryptionEngine<
        LweSecretKey32,
        LweCiphertextArray32,
        PlaintextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, PlaintextCount, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let mut plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array: LweCiphertextArray32 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_decrypt_lwe_ciphertext_array(&key, &mut plaintext_array, &ciphertext_array)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(18));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextArray32,
        input: &LweCiphertextArray32,
    ) -> Result<(), LweCiphertextArrayDiscardingDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_lwe_ciphertext_array_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextArray32,
        input: &LweCiphertextArray32,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextArrayDiscardingDecryptionEngine<
        LweSecretKey64,
        LweCiphertextArray64,
        PlaintextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, PlaintextCount, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let mut plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array: LweCiphertextArray64 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_decrypt_lwe_ciphertext_array(&key, &mut plaintext_array, &ciphertext_array)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(18));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextArray64,
        input: &LweCiphertextArray64,
    ) -> Result<(), LweCiphertextArrayDiscardingDecryptionError<Self::EngineError>> {
        LweCiphertextArrayDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_lwe_ciphertext_array_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextArray64,
        input: &LweCiphertextArray64,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}
