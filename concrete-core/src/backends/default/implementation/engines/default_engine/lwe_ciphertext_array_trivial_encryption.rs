use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::prelude::{
    DefaultEngine, LweCiphertextArray32, LweCiphertextArray64,
    LweCiphertextArrayTrivialEncryptionEngine, LweCiphertextArrayTrivialEncryptionError, LweSize,
    PlaintextArray32, PlaintextArray64,
};

impl LweCiphertextArrayTrivialEncryptionEngine<PlaintextArray32, LweCiphertextArray32>
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
    ///
    /// assert_eq!(ciphertext_array.lwe_dimension().to_lwe_size(), lwe_size);
    /// assert_eq!(
    ///     ciphertext_array.lwe_ciphertext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext_array(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray32,
    ) -> Result<LweCiphertextArray32, LweCiphertextArrayTrivialEncryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_array_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray32,
    ) -> LweCiphertextArray32 {
        let ciphertexts = ImplLweList::new_trivial_encryption(lwe_size, &input.0);

        LweCiphertextArray32(ciphertexts)
    }
}

impl LweCiphertextArrayTrivialEncryptionEngine<PlaintextArray64, LweCiphertextArray64>
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
    /// assert_eq!(ciphertext_array.lwe_dimension().to_lwe_size(), lwe_size);
    /// assert_eq!(
    ///     ciphertext_array.lwe_ciphertext_count().0,
    ///     plaintext_array.plaintext_count().0
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext_array(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray64,
    ) -> Result<LweCiphertextArray64, LweCiphertextArrayTrivialEncryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_array_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray64,
    ) -> LweCiphertextArray64 {
        let ciphertexts = ImplLweList::new_trivial_encryption(lwe_size, &input.0);

        LweCiphertextArray64(ciphertexts)
    }
}
