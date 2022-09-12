use super::ActivatedRandomGenerator;
use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    GlweSecretKey32, GlweSecretKey64, GlweSeededCiphertextArray32, GlweSeededCiphertextArray64,
    PlaintextArray32, PlaintextArray64,
};
use crate::commons::crypto::glwe::GlweSeededList as ImplGlweSeededList;
use crate::commons::math::random::{CompressionSeed, Seeder};
use crate::prelude::{CiphertextCount, Variance};
use crate::specification::engines::{
    GlweSeededCiphertextArrayEncryptionEngine, GlweSeededCiphertextArrayEncryptionError,
};
use crate::specification::entities::{GlweSecretKeyEntity, PlaintextArrayEntity};

/// # Description:
/// Implementation of [`GlweSeededCiphertextArrayEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    GlweSeededCiphertextArrayEncryptionEngine<
        GlweSecretKey32,
        PlaintextArray32,
        GlweSeededCiphertextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext_array =
    ///     engine.encrypt_glwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    /// #
    /// assert_eq!(
    /// #     seeded_ciphertext_array.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(seeded_ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext_array(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> Result<
        GlweSeededCiphertextArray32,
        GlweSeededCiphertextArrayEncryptionError<Self::EngineError>,
    > {
        GlweSeededCiphertextArrayEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_array_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextArray32,
        noise: Variance,
    ) -> GlweSeededCiphertextArray32 {
        let mut output = ImplGlweSeededList::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertextArray32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextArrayEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    GlweSeededCiphertextArrayEncryptionEngine<
        GlweSecretKey64,
        PlaintextArray64,
        GlweSeededCiphertextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext_array =
    ///     engine.encrypt_glwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    /// #
    /// assert_eq!(
    /// #     seeded_ciphertext_array.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(seeded_ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext_array(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> Result<
        GlweSeededCiphertextArray64,
        GlweSeededCiphertextArrayEncryptionError<Self::EngineError>,
    > {
        GlweSeededCiphertextArrayEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_array_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_array_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextArray64,
        noise: Variance,
    ) -> GlweSeededCiphertextArray64 {
        let mut output = ImplGlweSeededList::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertextArray64(output)
    }
}
