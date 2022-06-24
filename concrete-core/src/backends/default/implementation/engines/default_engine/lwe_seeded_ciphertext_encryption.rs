use super::ActivatedRandomGenerator;
use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    LweSecretKey32, LweSecretKey64, LweSeededCiphertext32, LweSeededCiphertext64, Plaintext32,
    Plaintext64,
};
use crate::commons::crypto::lwe::LweSeededCiphertext as ImplLweSeededCiphertext;
use crate::commons::math::random::{CompressionSeed, Seeder};
use crate::specification::engines::{
    LweSeededCiphertextEncryptionEngine, LweSeededCiphertextEncryptionError,
};
use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::dispersion::Variance;

/// # Description:
/// Implementation of [`LweSeededCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl LweSeededCiphertextEncryptionEngine<LweSecretKey32, Plaintext32, LweSeededCiphertext32>
    for DefaultEngine
{
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
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
    fn encrypt_lwe_seeded_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<LweSeededCiphertext32, LweSeededCiphertextEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
    ) -> LweSeededCiphertext32 {
        let mut output = ImplLweSeededCiphertext::allocate(
            key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe::<_, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        LweSeededCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl LweSeededCiphertextEncryptionEngine<LweSecretKey64, Plaintext64, LweSeededCiphertext64>
    for DefaultEngine
{
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
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
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
    fn encrypt_lwe_seeded_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<LweSeededCiphertext64, LweSeededCiphertextEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> LweSeededCiphertext64 {
        let mut output = ImplLweSeededCiphertext::allocate(
            key.lwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe::<_, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        LweSeededCiphertext64(output)
    }
}
