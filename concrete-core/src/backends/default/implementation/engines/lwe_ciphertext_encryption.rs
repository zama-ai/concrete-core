use concrete_commons::dispersion::Variance;

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweSecretKey32, LweSecretKey64, Plaintext32, Plaintext64,
};
use crate::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::specification::engines::{LweCiphertextEncryptionEngine, LweCiphertextEncryptionError};
use crate::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweCiphertextEncryptionEngine<LweSecretKey32, Plaintext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new((
    ///     RandomGeneratorImplementation::Software,
    ///     Box::new(UnixSeeder::new(UNSAFE_SECRET)),
    /// ))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<LweCiphertext32, LweCiphertextEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.encrypt_lwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
    ) -> LweCiphertext32 {
        let mut ciphertext = ImplLweCiphertext::allocate(0u32, key.lwe_dimension().to_lwe_size());
        key.0.encrypt_lwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweCiphertextEncryptionEngine<LweSecretKey64, Plaintext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new((
    ///     RandomGeneratorImplementation::Software,
    ///     Box::new(UnixSeeder::new(UNSAFE_SECRET)),
    /// ))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<LweCiphertext64, LweCiphertextEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.encrypt_lwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> LweCiphertext64 {
        let mut ciphertext = ImplLweCiphertext::allocate(0u64, key.lwe_dimension().to_lwe_size());
        key.0.encrypt_lwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertext64(ciphertext)
    }
}
