use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

use crate::backends::aesni::implementation::engines::AesniEngine;
use crate::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::prelude::{GlweSecretKey32, GlweSecretKey64, GlweSecretKeyEntity, LweBootstrapKey32, LweBootstrapKey64, LweSecretKey32, LweSecretKey64, LweSecretKeyEntity};
use crate::specification::engines::{LweBootstrapKeyCreationEngine, LweBootstrapKeyCreationError};

/// # Description:
/// Implementation of [`LweBootstrapKeyCreationEngine`] for [`AesniEngine`] that operates on
/// 32 bits integers. It outputs a bootstrap key in the standard domain.
impl LweBootstrapKeyCreationEngine<LweSecretKey32, GlweSecretKey32, LweBootstrapKey32>
    for AesniEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = aesni_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = aesni_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey32 =
    ///     aesni_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// #
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey32, LweBootstrapKeyCreationError<Self::EngineError>> {
        LweBootstrapKeyCreationError::perform_generic_checks(
            decomposition_base_log,
            decomposition_level_count,
            32,
        )?;
        Ok(unsafe {
            self.create_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn create_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey32 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.glwe_dimension().to_glwe_size(),
            output_key.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey32(key)
    }
}

/// # Description:
/// Implementation of [`LweBootstrapKeyCreationEngine`] for [`AesniEngine`] that operates on
/// 64 bits integers. It outputs a bootstrap key in the standard domain.
impl LweBootstrapKeyCreationEngine<LweSecretKey64, GlweSecretKey64, LweBootstrapKey64>
    for AesniEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut aesni_engine = AesniEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = aesni_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = aesni_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey64 =
    ///     aesni_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// #
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey64, LweBootstrapKeyCreationError<Self::EngineError>> {
        LweBootstrapKeyCreationError::perform_generic_checks(
            decomposition_base_log,
            decomposition_level_count,
            64,
        )?;
        Ok(unsafe {
            self.create_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn create_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey64 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.glwe_dimension().to_glwe_size(),
            output_key.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey64(key)
    }
}
