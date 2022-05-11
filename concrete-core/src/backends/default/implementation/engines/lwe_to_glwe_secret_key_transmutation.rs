use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    GlweSecretKey32, GlweSecretKey64, LweSecretKey32, LweSecretKey64,
};
use crate::commons::crypto::secret::GlweSecretKey as ImpleGlweSecretKey;
use crate::commons::math::tensor::IntoTensor;
use crate::specification::engines::{
    LweToGlweSecretKeyTransmutationEngine, LweToGlweSecretKeyTransmutationEngineError,
};
use concrete_commons::parameters::PolynomialSize;

impl LweToGlweSecretKeyTransmutationEngine<LweSecretKey32, GlweSecretKey32> for DefaultEngine {
    /// # Example
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(8);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let lwe_secret_key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    ///
    /// let glwe_secret_key =
    ///     engine.transmute_lwe_secret_key_to_glwe_secret_key(lwe_secret_key, polynomial_size)?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), GlweDimension(2));
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// engine.destroy(glwe_secret_key)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_secret_key: LweSecretKey32,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey32, LweToGlweSecretKeyTransmutationEngineError<Self::EngineError>>
    {
        LweToGlweSecretKeyTransmutationEngineError::perform_generic_checks(
            &lwe_secret_key,
            polynomial_size,
        )?;
        Ok(unsafe {
            self.transmute_lwe_secret_key_to_glwe_secret_key_unchecked(
                lwe_secret_key,
                polynomial_size,
            )
        })
    }

    unsafe fn transmute_lwe_secret_key_to_glwe_secret_key_unchecked(
        &mut self,
        lwe_secret_key: LweSecretKey32,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey32 {
        let LweSecretKey32(impl_lwe_key) = lwe_secret_key;
        let lwe_key_container = impl_lwe_key.into_tensor().into_container();
        GlweSecretKey32(ImpleGlweSecretKey::binary_from_container(
            lwe_key_container,
            polynomial_size,
        ))
    }
}

impl LweToGlweSecretKeyTransmutationEngine<LweSecretKey64, GlweSecretKey64> for DefaultEngine {
    /// # Example
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(8);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let lwe_secret_key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    ///
    /// let glwe_secret_key =
    ///     engine.transmute_lwe_secret_key_to_glwe_secret_key(lwe_secret_key, polynomial_size)?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), GlweDimension(2));
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// engine.destroy(glwe_secret_key)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_secret_key: LweSecretKey64,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey64, LweToGlweSecretKeyTransmutationEngineError<Self::EngineError>>
    {
        LweToGlweSecretKeyTransmutationEngineError::perform_generic_checks(
            &lwe_secret_key,
            polynomial_size,
        )?;
        Ok(unsafe {
            self.transmute_lwe_secret_key_to_glwe_secret_key_unchecked(
                lwe_secret_key,
                polynomial_size,
            )
        })
    }

    unsafe fn transmute_lwe_secret_key_to_glwe_secret_key_unchecked(
        &mut self,
        lwe_secret_key: LweSecretKey64,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey64 {
        let LweSecretKey64(impl_lwe_key) = lwe_secret_key;
        let lwe_key_container = impl_lwe_key.into_tensor().into_container();
        GlweSecretKey64(ImpleGlweSecretKey::binary_from_container(
            lwe_key_container,
            polynomial_size,
        ))
    }
}
