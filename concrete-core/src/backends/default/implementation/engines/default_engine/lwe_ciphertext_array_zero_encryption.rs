use crate::prelude::{CiphertextCount, LweCiphertextCount, PlaintextCount, Variance};

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertextArray32, LweCiphertextArray64, LweSecretKey32, LweSecretKey64,
};
use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::specification::engines::{
    LweCiphertextArrayZeroEncryptionEngine, LweCiphertextArrayZeroEncryptionError,
};
use crate::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextArrayZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextArrayZeroEncryptionEngine<LweSecretKey32, LweCiphertextArray32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let ciphertext_count = LweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_array =
    ///     engine.zero_encrypt_lwe_ciphertext_array(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_array.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextArray32, LweCiphertextArrayZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextArrayZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_array_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextArray32 {
        let mut array = ImplLweList::allocate(
            0u32,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u32, PlaintextCount(count.0));
        key.0.encrypt_lwe_list(
            &mut array,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextArray32(array)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextArrayZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextArrayZeroEncryptionEngine<LweSecretKey64, LweCiphertextArray64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let ciphertext_count = LweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_array =
    ///     engine.zero_encrypt_lwe_ciphertext_array(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_array.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextArray64, LweCiphertextArrayZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextArrayZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_array_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextArray64 {
        let mut array = ImplLweList::allocate(
            0u64,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u64, PlaintextCount(count.0));
        key.0.encrypt_lwe_list(
            &mut array,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextArray64(array)
    }
}
