use super::ActivatedRandomGenerator;
use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    LweCiphertextArray32, LweCiphertextArray64, LweSeededCiphertextArray32,
    LweSeededCiphertextArray64,
};
use crate::commons::crypto::lwe::LweList as ImplLweList;
use crate::prelude::CiphertextCount;
use crate::specification::engines::{
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine,
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationError,
};
use crate::specification::entities::LweSeededCiphertextArrayEntity;

/// # Description:
/// Implementation of [`LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine<
        LweSeededCiphertextArray32,
        LweCiphertextArray32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let mut seeded_ciphertext_array: LweSeededCiphertextArray32 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let ciphertext_array = engine
    ///     .transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(seeded_ciphertext_array)?;
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_seeded_ciphertext_array: LweSeededCiphertextArray32,
    ) -> Result<
        LweCiphertextArray32,
        LweSeededCiphertextArrayToLweCiphertextArrayTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
                lwe_seeded_ciphertext_array,
            )
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_seeded_ciphertext_array: LweSeededCiphertextArray32,
    ) -> LweCiphertextArray32 {
        let mut output_ciphertext_array = ImplLweList::allocate(
            0_u32,
            lwe_seeded_ciphertext_array.lwe_dimension().to_lwe_size(),
            CiphertextCount(lwe_seeded_ciphertext_array.lwe_ciphertext_count().0),
        );
        lwe_seeded_ciphertext_array
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output_ciphertext_array);

        LweCiphertextArray32(output_ciphertext_array)
    }
}

/// # Description:
/// Implementation of [`LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine<
        LweSeededCiphertextArray64,
        LweCiphertextArray64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let mut seeded_ciphertext_array: LweSeededCiphertextArray64 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let ciphertext_array = engine
    ///     .transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(seeded_ciphertext_array)?;
    /// assert_eq!(ciphertext_array.lwe_dimension(), lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_seeded_ciphertext_array: LweSeededCiphertextArray64,
    ) -> Result<
        LweCiphertextArray64,
        LweSeededCiphertextArrayToLweCiphertextArrayTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
                lwe_seeded_ciphertext_array,
            )
        })
    }

    unsafe fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_seeded_ciphertext_array: LweSeededCiphertextArray64,
    ) -> LweCiphertextArray64 {
        let mut output_ciphertext_array = ImplLweList::allocate(
            0_u64,
            lwe_seeded_ciphertext_array.lwe_dimension().to_lwe_size(),
            CiphertextCount(lwe_seeded_ciphertext_array.lwe_ciphertext_count().0),
        );
        lwe_seeded_ciphertext_array
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output_ciphertext_array);

        LweCiphertextArray64(output_ciphertext_array)
    }
}
