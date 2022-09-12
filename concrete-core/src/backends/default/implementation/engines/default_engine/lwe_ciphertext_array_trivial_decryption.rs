use crate::commons::crypto::encoding::{Plaintext, PlaintextList as ImplPlaintextList};
use crate::prelude::{
    DefaultEngine, LweCiphertextArray32, LweCiphertextArray64, LweCiphertextArrayEntity,
    LweCiphertextArrayTrivialDecryptionEngine, LweCiphertextArrayTrivialDecryptionError,
    PlaintextArray32, PlaintextArray64, PlaintextCount,
};

impl LweCiphertextArrayTrivialDecryptionEngine<LweCiphertextArray32, PlaintextArray32>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use concrete_core::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_array: LweCiphertextArray32 =
    ///     engine.trivially_encrypt_lwe_ciphertext_array(lwe_size, &plaintext_array)?;
    /// let output: PlaintextArray32 =
    ///     engine.trivially_decrypt_lwe_ciphertext_array(&ciphertext_array)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(3));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext_array(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> Result<PlaintextArray32, LweCiphertextArrayTrivialDecryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_array_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> PlaintextArray32 {
        let count = PlaintextCount(input.lwe_ciphertext_count().0);
        let mut output = ImplPlaintextList::allocate(0u32, count);
        for (plaintext, ciphertext) in output.plaintext_iter_mut().zip(input.0.ciphertext_iter()) {
            *plaintext = Plaintext(ciphertext.get_body().0);
        }
        PlaintextArray32(output)
    }
}

impl LweCiphertextArrayTrivialDecryptionEngine<LweCiphertextArray64, PlaintextArray64>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use concrete_core::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = vec![3_u64 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_array: LweCiphertextArray64 =
    ///     engine.trivially_encrypt_lwe_ciphertext_array(lwe_size, &plaintext_array)?;
    ///
    /// let output: PlaintextArray64 =
    ///     engine.trivially_decrypt_lwe_ciphertext_array(&ciphertext_array)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(3));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext_array(
        &mut self,
        input: &LweCiphertextArray64,
    ) -> Result<PlaintextArray64, LweCiphertextArrayTrivialDecryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_array_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &LweCiphertextArray64,
    ) -> PlaintextArray64 {
        let count = PlaintextCount(input.lwe_ciphertext_count().0);
        let mut output = ImplPlaintextList::allocate(0u64, count);
        for (plaintext, ciphertext) in output.plaintext_iter_mut().zip(input.0.ciphertext_iter()) {
            *plaintext = Plaintext(ciphertext.get_body().0);
        }
        PlaintextArray64(output)
    }
}
