use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::prelude::{
    DefaultEngine, GlweCiphertextArray32, GlweCiphertextArray64, GlweCiphertextArrayEntity,
    GlweCiphertextArrayTrivialDecryptionEngine, GlweCiphertextArrayTrivialDecryptionError,
    PlaintextArray32, PlaintextArray64, PlaintextCount,
};

impl GlweCiphertextArrayTrivialDecryptionEngine<GlweCiphertextArray32, PlaintextArray32>
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
    /// let output: PlaintextArray32 =
    ///     engine.trivially_decrypt_glwe_ciphertext_array(&ciphertext_array)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext_array(
        &mut self,
        input: &GlweCiphertextArray32,
    ) -> Result<PlaintextArray32, GlweCiphertextArrayTrivialDecryptionError<Self::EngineError>>
    {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &GlweCiphertextArray32,
    ) -> PlaintextArray32 {
        let count = PlaintextCount(input.glwe_ciphertext_count().0 * input.polynomial_size().0);
        let sub_count = PlaintextCount(input.polynomial_size().0);
        let mut output = ImplPlaintextList::allocate(0u32, count);
        for (mut plaintext, ciphertext) in output
            .sublist_iter_mut(sub_count)
            .zip(input.0.ciphertext_iter())
        {
            plaintext
                .as_mut_tensor()
                .fill_with_copy(ciphertext.get_body().as_tensor());
        }
        PlaintextArray32(output)
    }
}

impl GlweCiphertextArrayTrivialDecryptionEngine<GlweCiphertextArray64, PlaintextArray64>
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
    /// let output: PlaintextArray64 =
    ///     engine.trivially_decrypt_glwe_ciphertext_array(&ciphertext_array)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext_array(
        &mut self,
        input: &GlweCiphertextArray64,
    ) -> Result<PlaintextArray64, GlweCiphertextArrayTrivialDecryptionError<Self::EngineError>>
    {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &GlweCiphertextArray64,
    ) -> PlaintextArray64 {
        let count = PlaintextCount(input.glwe_ciphertext_count().0 * input.polynomial_size().0);
        let sub_count = PlaintextCount(input.polynomial_size().0);
        let mut output = ImplPlaintextList::allocate(0u64, count);
        for (mut plaintext, ciphertext) in output
            .sublist_iter_mut(sub_count)
            .zip(input.0.ciphertext_iter())
        {
            plaintext
                .as_mut_tensor()
                .fill_with_copy(ciphertext.get_body().as_tensor());
        }
        PlaintextArray64(output)
    }
}
