#[allow(deprecated)]
use concrete_commons::parameters::{MonomialDegree, MonomialIndex, LweDimension};

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertext32, LweCiphertext64,
};
use crate::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::specification::engines::{
    LweCiphertextSampleExtractionEngine, LweCiphertextSampleExtractionError,
};
use crate::specification::entities::GlweCiphertextEntity;

/// # Description:
/// Implementation of [`LweCiphertextSampleExtractionEngine`] for [`CoreEngine`] that operates
/// on 32 bits integers.
impl LweCiphertextSampleExtractionEngine<GlweCiphertext32, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     GlweDimension, LweDimension, MonomialIndex, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_key: GlweSecretKey32 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let glwe_ciphertext = engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)?;
    ///
    /// // We extract the first sample from the GLWE ciphertext
    /// let lwe_ciphertext = engine.sample_extract_lwe_ciphertext(
    ///     &glwe_ciphertext,
    ///     MonomialIndex(0),
    /// )?;
    /// #
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(glwe_key)?;
    /// engine.destroy(lwe_key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(glwe_ciphertext)?;
    /// engine.destroy(lwe_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn sample_extract_lwe_ciphertext(
        &mut self,
        input: &GlweCiphertext32,
        nth: MonomialIndex,
    ) -> Result<LweCiphertext32, LweCiphertextSampleExtractionError<Self::EngineError>> {
        LweCiphertextSampleExtractionError::perform_generic_checks(input, nth)?;
        Ok(unsafe { self.sample_extract_lwe_ciphertext_unchecked(input, nth) })
    }

    unsafe fn sample_extract_lwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext32,
        nth: MonomialIndex,
    ) -> LweCiphertext32 {
        let mut lwe_ct = LweCiphertext32(ImplLweCiphertext::allocate(
            0u32,
            LweDimension(input.polynomial_size().0 * input.glwe_dimension().0
            )
                .to_lwe_size()));
        #[allow(deprecated)]
        lwe_ct
            .0
            .fill_with_glwe_sample_extraction(&input.0, MonomialDegree(nth.0));
        lwe_ct
    }
}

/// # Description:
/// Implementation of [`LweCiphertextSampleExtractionEngine`] for [`CoreEngine`] that operates
/// on 64 bits integers.
impl LweCiphertextSampleExtractionEngine<GlweCiphertext64, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     GlweDimension, LweDimension, MonomialIndex, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_key: GlweSecretKey64 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let glwe_ciphertext = engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)?;
    ///
    /// // We extract the first sample from the GLWE ciphertext
    /// let lwe_ciphertext = engine.sample_extract_lwe_ciphertext(
    ///     &glwe_ciphertext,
    ///     MonomialIndex(0),
    /// )?;
    /// #
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    ///
    /// engine.destroy(glwe_key)?;
    /// engine.destroy(lwe_key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(glwe_ciphertext)?;
    /// engine.destroy(lwe_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn sample_extract_lwe_ciphertext(
        &mut self,
        input: &GlweCiphertext64,
        nth: MonomialIndex,
    ) -> Result<LweCiphertext64, LweCiphertextSampleExtractionError<Self::EngineError>> {
        LweCiphertextSampleExtractionError::perform_generic_checks(input, nth)?;
        Ok(unsafe { self.sample_extract_lwe_ciphertext_unchecked(input, nth) })
    }

    unsafe fn sample_extract_lwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext64,
        nth: MonomialIndex,
    ) -> LweCiphertext64 {
        let mut lwe_ct = LweCiphertext64(ImplLweCiphertext::allocate(
            0u64,
            LweDimension(input.polynomial_size().0 * input.glwe_dimension().0
            )
                .to_lwe_size()));
        #[allow(deprecated)]
        lwe_ct
            .0
            .fill_with_glwe_sample_extraction(&input.0, MonomialDegree(nth.0));
        lwe_ct
    }
}
