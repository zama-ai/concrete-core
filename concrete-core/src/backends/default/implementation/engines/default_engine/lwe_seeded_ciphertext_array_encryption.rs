use crate::prelude::{CiphertextCount, Variance};

use super::ActivatedRandomGenerator;
use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64, LweSeededCiphertextArray32, LweSeededCiphertextArray64,
    PlaintextArray32, PlaintextArray64,
};
use crate::commons::crypto::lwe::LweSeededList as ImplLweSeededList;
use crate::commons::math::random::{CompressionSeed, Seeder};
use crate::specification::engines::{
    LweSeededCiphertextArrayEncryptionEngine, LweSeededCiphertextArrayEncryptionError,
};
use crate::specification::entities::{LweSecretKeyEntity, PlaintextArrayEntity};

/// # Description:
/// Implementation of [`LweSeededCiphertextArrayEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweSeededCiphertextArrayEncryptionEngine<
        LweSecretKey32,
        PlaintextArray32,
        LweSeededCiphertextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweSeededCiphertextArray32 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #    ciphertext_array.lwe_ciphertext_count(),
    /// #    LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_lwe_seeded_ciphertext_array(
        &mut self,
        key: &LweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> Result<
        LweSeededCiphertextArray32,
        LweSeededCiphertextArrayEncryptionError<Self::EngineError>,
    > {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_array_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> LweSeededCiphertextArray32 {
        let mut array = ImplLweSeededList::allocate(
            key.lwe_dimension(),
            CiphertextCount(input.plaintext_count().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut array,
                &input.0,
                noise,
                &mut self.seeder,
            );
        LweSeededCiphertextArray32(array)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextArrayEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweSeededCiphertextArrayEncryptionEngine<
        LweSecretKey64,
        PlaintextArray64,
        LweSeededCiphertextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweSeededCiphertextArray64 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    /// #
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    /// #     ciphertext_array.lwe_ciphertext_count(),
    /// #     LweCiphertextCount(3)
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_lwe_seeded_ciphertext_array(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> Result<
        LweSeededCiphertextArray64,
        LweSeededCiphertextArrayEncryptionError<Self::EngineError>,
    > {
        Ok(unsafe { self.encrypt_lwe_seeded_ciphertext_array_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_lwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> LweSeededCiphertextArray64 {
        let mut array = ImplLweSeededList::allocate(
            key.lwe_dimension(),
            CiphertextCount(input.plaintext_count().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );
        key.0
            .encrypt_seeded_lwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut array,
                &input.0,
                noise,
                &mut self.seeder,
            );
        LweSeededCiphertextArray64(array)
    }
}
