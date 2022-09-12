use crate::prelude::GlweSize;

use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    GlweCiphertextArray32, GlweCiphertextArray64, PlaintextArray32, PlaintextArray64,
};
use crate::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::prelude::{CiphertextCount, GlweCiphertextCount, PlaintextArrayEntity, PolynomialSize};
use crate::specification::engines::{
    GlweCiphertextArrayTrivialEncryptionEngine, GlweCiphertextArrayTrivialEncryptionError,
};

impl GlweCiphertextArrayTrivialEncryptionEngine<PlaintextArray32, GlweCiphertextArray32>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let input = vec![3_u32 << 20; 2 * polynomial_size.0];
    /// let ciphertext_count = GlweCiphertextCount(2);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_array: GlweCiphertextArray32 = engine.trivially_encrypt_glwe_ciphertext_array(
    ///     glwe_dimension.to_glwe_size(),
    ///     ciphertext_count,
    ///     &plaintext_array,
    /// )?;
    ///
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_ciphertext_count(), ciphertext_count);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray32,
    ) -> Result<GlweCiphertextArray32, GlweCiphertextArrayTrivialEncryptionError<Self::EngineError>>
    {
        GlweCiphertextArrayTrivialEncryptionError::perform_generic_checks(
            glwe_ciphertext_count,
            input,
        )?;
        unsafe {
            Ok(self.trivially_encrypt_glwe_ciphertext_array_unchecked(
                glwe_size,
                glwe_ciphertext_count,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray32,
    ) -> GlweCiphertextArray32 {
        let mut ciphertext_array: ImplGlweList<Vec<u32>> = ImplGlweList::allocate(
            0_u32,
            PolynomialSize(input.plaintext_count().0 / glwe_ciphertext_count.0),
            glwe_size.to_glwe_dimension(),
            CiphertextCount(glwe_ciphertext_count.0),
        );
        ciphertext_array.fill_with_trivial_encryption(&input.0);
        GlweCiphertextArray32(ciphertext_array)
    }
}

impl GlweCiphertextArrayTrivialEncryptionEngine<PlaintextArray64, GlweCiphertextArray64>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let input = vec![3_u64 << 50; 2 * polynomial_size.0];
    /// let ciphertext_count = GlweCiphertextCount(2);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_array: GlweCiphertextArray64 = engine.trivially_encrypt_glwe_ciphertext_array(
    ///     glwe_dimension.to_glwe_size(),
    ///     ciphertext_count,
    ///     &plaintext_array,
    /// )?;
    ///
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_ciphertext_count(), ciphertext_count);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray64,
    ) -> Result<GlweCiphertextArray64, GlweCiphertextArrayTrivialEncryptionError<Self::EngineError>>
    {
        GlweCiphertextArrayTrivialEncryptionError::perform_generic_checks(
            glwe_ciphertext_count,
            input,
        )?;
        unsafe {
            Ok(self.trivially_encrypt_glwe_ciphertext_array_unchecked(
                glwe_size,
                glwe_ciphertext_count,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray64,
    ) -> GlweCiphertextArray64 {
        let mut ciphertext_array: ImplGlweList<Vec<u64>> = ImplGlweList::allocate(
            0_u64,
            PolynomialSize(input.plaintext_count().0 / glwe_ciphertext_count.0),
            glwe_size.to_glwe_dimension(),
            CiphertextCount(glwe_ciphertext_count.0),
        );
        ciphertext_array.fill_with_trivial_encryption(&input.0);
        GlweCiphertextArray64(ciphertext_array)
    }
}
