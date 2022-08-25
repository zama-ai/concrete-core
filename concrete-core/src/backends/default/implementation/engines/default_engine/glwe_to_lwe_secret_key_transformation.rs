use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    GlweSecretKey32, GlweSecretKey64, LweSecretKey32, LweSecretKey64,
};
use crate::specification::engines::{
    GlweToLweSecretKeyTransformationEngine, GlweToLweSecretKeyTransformationEngineError,
};

impl GlweToLweSecretKeyTransformationEngine<GlweSecretKey32, LweSecretKey32> for DefaultEngine {
    /// # Example
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let glwe_secret_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// let lwe_secret_key = engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), LweDimension(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_secret_key: GlweSecretKey32,
    ) -> Result<LweSecretKey32, GlweToLweSecretKeyTransformationEngineError<Self::EngineError>>
    {
        Ok(unsafe { self.transform_glwe_secret_key_to_lwe_secret_key_unchecked(glwe_secret_key) })
    }

    unsafe fn transform_glwe_secret_key_to_lwe_secret_key_unchecked(
        &mut self,
        glwe_secret_key: GlweSecretKey32,
    ) -> LweSecretKey32 {
        LweSecretKey32(glwe_secret_key.0.into_lwe_secret_key())
    }
}

impl GlweToLweSecretKeyTransformationEngine<GlweSecretKey64, LweSecretKey64> for DefaultEngine {
    /// # Example
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let glwe_secret_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// let lwe_secret_key = engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), LweDimension(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_secret_key: GlweSecretKey64,
    ) -> Result<LweSecretKey64, GlweToLweSecretKeyTransformationEngineError<Self::EngineError>>
    {
        Ok(unsafe { self.transform_glwe_secret_key_to_lwe_secret_key_unchecked(glwe_secret_key) })
    }

    unsafe fn transform_glwe_secret_key_to_lwe_secret_key_unchecked(
        &mut self,
        glwe_secret_key: GlweSecretKey64,
    ) -> LweSecretKey64 {
        LweSecretKey64(glwe_secret_key.0.into_lwe_secret_key())
    }
}
