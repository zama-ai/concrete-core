use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    GlweCiphertextArray32, GlweCiphertextArray64, GlweSecretKey32, GlweSecretKey64,
    PlaintextArray32, PlaintextArray64,
};
use crate::specification::engines::{
    GlweCiphertextArrayDiscardingDecryptionEngine, GlweCiphertextArrayDiscardingDecryptionError,
};

/// # Description:
/// Implementation of [`GlweCiphertextArrayDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    GlweCiphertextArrayDiscardingDecryptionEngine<
        GlweSecretKey32,
        GlweCiphertextArray32,
        PlaintextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PlaintextCount, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let mut plaintext_array = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array = engine.encrypt_glwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_decrypt_glwe_ciphertext_array(&key, &mut plaintext_array, &ciphertext_array)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(8));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_glwe_ciphertext_array(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextArray32,
        input: &GlweCiphertextArray32,
    ) -> Result<(), GlweCiphertextArrayDiscardingDecryptionError<Self::EngineError>> {
        GlweCiphertextArrayDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_glwe_ciphertext_array_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextArray32,
        input: &GlweCiphertextArray32,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextArrayDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    GlweCiphertextArrayDiscardingDecryptionEngine<
        GlweSecretKey64,
        GlweCiphertextArray64,
        PlaintextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PlaintextCount, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let mut plaintext_array = engine.create_plaintext_array_from(&input)?;
    /// let ciphertext_array = engine.encrypt_glwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// engine.discard_decrypt_glwe_ciphertext_array(&key, &mut plaintext_array, &ciphertext_array)?;
    /// #
    /// assert_eq!(plaintext_array.plaintext_count(), PlaintextCount(8));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_glwe_ciphertext_array(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextArray64,
        input: &GlweCiphertextArray64,
    ) -> Result<(), GlweCiphertextArrayDiscardingDecryptionError<Self::EngineError>> {
        GlweCiphertextArrayDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_glwe_ciphertext_array_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextArray64,
        input: &GlweCiphertextArray64,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}
