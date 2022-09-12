use crate::prelude::{CiphertextCount, GlweCiphertextCount, Variance};

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    GlweCiphertextArray32, GlweCiphertextArray64, GlweSecretKey32, GlweSecretKey64,
};
use crate::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::specification::engines::{
    GlweCiphertextArrayZeroEncryptionEngine, GlweCiphertextArrayZeroEncryptionError,
};
use crate::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweCiphertextArrayZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl GlweCiphertextArrayZeroEncryptionEngine<GlweSecretKey32, GlweCiphertextArray32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext_array =
    ///     engine.zero_encrypt_glwe_ciphertext_array(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_array.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext_array(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<GlweCiphertextArray32, GlweCiphertextArrayZeroEncryptionError<Self::EngineError>>
    {
        GlweCiphertextArrayZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_array_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> GlweCiphertextArray32 {
        let mut ciphertext_array = ImplGlweList::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(count.0),
        );
        key.0
            .encrypt_zero_glwe_list(&mut ciphertext_array, noise, &mut self.encryption_generator);
        GlweCiphertextArray32(ciphertext_array)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextArrayZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl GlweCiphertextArrayZeroEncryptionEngine<GlweSecretKey64, GlweCiphertextArray64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext_array =
    ///     engine.zero_encrypt_glwe_ciphertext_array(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_array.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext_array(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<GlweCiphertextArray64, GlweCiphertextArrayZeroEncryptionError<Self::EngineError>>
    {
        GlweCiphertextArrayZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_array_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> GlweCiphertextArray64 {
        let mut ciphertext_array = ImplGlweList::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(count.0),
        );
        key.0
            .encrypt_zero_glwe_list(&mut ciphertext_array, noise, &mut self.encryption_generator);
        GlweCiphertextArray64(ciphertext_array)
    }
}
