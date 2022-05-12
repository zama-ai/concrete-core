use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{CiphertextCount, LweCiphertextCount, PlaintextCount};

use crate::backends::aesni::implementation::engines::AesniEngine;
use crate::prelude::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
};
use crate::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::specification::engines::{
    LweCiphertextVectorZeroEncryptionEngine, LweCiphertextVectorZeroEncryptionError,
};
use crate::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextVectorZeroEncryptionEngine`] for [`AesniEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextVectorZeroEncryptionEngine<LweSecretKey32, LweCiphertextVector32>
    for AesniEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
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
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = aesni_engine.create_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_vector =
    ///     aesni_engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_vector.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextVector32 {
        let mut vector = ImplLweList::allocate(
            0u32,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u32, PlaintextCount(count.0));
        key.0.encrypt_lwe_list(
            &mut vector,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextVector32(vector)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorZeroEncryptionEngine`] for [`AesniEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextVectorZeroEncryptionEngine<LweSecretKey64, LweCiphertextVector64>
    for AesniEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
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
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = aesni_engine.create_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_vector =
    ///     aesni_engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_vector.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(ciphertext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextVector64 {
        let mut vector = ImplLweList::allocate(
            0u64,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u64, PlaintextCount(count.0));
        key.0.encrypt_lwe_list(
            &mut vector,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextVector64(vector)
    }
}
