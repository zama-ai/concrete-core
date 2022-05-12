use concrete_commons::dispersion::Variance;

use crate::backends::aesni::implementation::engines::AesniEngine;
use crate::prelude::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32,
    PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextDiscardingEncryptionEngine, GlweCiphertextDiscardingEncryptionError,
};

/// # Description:
/// Implementation of [`GlweCiphertextDiscardingEncryptionEngine`] for [`AesniEngine`] that
/// operates on 32 bits integers.
impl GlweCiphertextDiscardingEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertext32>
    for AesniEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 4];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key_1: GlweSecretKey32 = aesni_engine.create_glwe_secret_key(glwe_dimension, 
    /// polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    /// let mut ciphertext = aesni_engine.encrypt_glwe_ciphertext(&key_1, &plaintext_vector, 
    /// noise)?;
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey32 = aesni_engine.create_glwe_secret_key(glwe_dimension, 
    /// polynomial_size)?;
    ///
    /// aesni_engine.discard_encrypt_glwe_ciphertext(&key_2, &mut ciphertext, &plaintext_vector, 
    /// noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(ciphertext)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(key_1)?;
    /// default_engine.destroy(key_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), GlweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_glwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_glwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextDiscardingEncryptionEngine`] for [`AesniEngine`] that
/// operates on 64 bits integers.
impl GlweCiphertextDiscardingEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertext64>
    for AesniEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 4];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key_1: GlweSecretKey64 = aesni_engine.create_glwe_secret_key(glwe_dimension, 
    /// polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    /// let mut ciphertext = aesni_engine.encrypt_glwe_ciphertext(&key_1, &plaintext_vector, 
    /// noise)?;
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey64 = aesni_engine.create_glwe_secret_key(glwe_dimension, 
    /// polynomial_size)?;
    ///
    /// aesni_engine.discard_encrypt_glwe_ciphertext(&key_2, &mut ciphertext, &plaintext_vector, 
    /// noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(ciphertext)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(key_1)?;
    /// default_engine.destroy(key_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), GlweCiphertextDiscardingEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingEncryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_encrypt_glwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_glwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
