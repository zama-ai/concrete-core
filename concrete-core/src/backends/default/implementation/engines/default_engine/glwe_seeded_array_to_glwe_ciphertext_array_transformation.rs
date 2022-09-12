use super::ActivatedRandomGenerator;
use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    GlweCiphertextArray32, GlweCiphertextArray64, GlweSeededCiphertextArray32,
    GlweSeededCiphertextArray64,
};
use crate::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::prelude::CiphertextCount;
use crate::specification::engines::{
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine,
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError,
};
use crate::specification::entities::GlweSeededCiphertextArrayEntity;

/// # Description:
/// Implementation of [`GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
impl
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine<
        GlweSeededCiphertextArray32,
        GlweCiphertextArray32,
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
    ///
    /// let ciphertext_array = engine.transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(seeded_ciphertext_array)?;
    ///
    /// assert_eq!(
    /// #     ciphertext_array.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_seeded_ciphertext_array: GlweSeededCiphertextArray32,
    ) -> Result<
        GlweCiphertextArray32,
        GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array_unchecked(
                glwe_seeded_ciphertext_array,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_seeded_ciphertext_array: GlweSeededCiphertextArray32,
    ) -> GlweCiphertextArray32 {
        let mut output = ImplGlweList::allocate(
            0,
            glwe_seeded_ciphertext_array.polynomial_size(),
            glwe_seeded_ciphertext_array.glwe_dimension(),
            CiphertextCount(glwe_seeded_ciphertext_array.glwe_ciphertext_count().0),
        );

        glwe_seeded_ciphertext_array
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertextArray32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
impl
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine<
        GlweSeededCiphertextArray64,
        GlweCiphertextArray64,
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
    ///
    /// let ciphertext_array = engine.transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(seeded_ciphertext_array)?;
    ///
    /// assert_eq!(
    /// #     ciphertext_array.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(ciphertext_array.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_array.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_seeded_ciphertext_array: GlweSeededCiphertextArray64,
    ) -> Result<
        GlweCiphertextArray64,
        GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationError<Self::EngineError>,
    > {
        Ok(unsafe {
            self.transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array_unchecked(
                glwe_seeded_ciphertext_array,
            )
        })
    }

    unsafe fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_seeded_ciphertext_array: GlweSeededCiphertextArray64,
    ) -> GlweCiphertextArray64 {
        let mut output = ImplGlweList::allocate(
            0,
            glwe_seeded_ciphertext_array.polynomial_size(),
            glwe_seeded_ciphertext_array.glwe_dimension(),
            CiphertextCount(glwe_seeded_ciphertext_array.glwe_ciphertext_count().0),
        );

        glwe_seeded_ciphertext_array
            .0
            .expand_into::<_, _, ActivatedRandomGenerator>(&mut output);

        GlweCiphertextArray64(output)
    }
}
