use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{FftwFourierLweBootstrapKey32, FftwFourierLweBootstrapKey64};
use crate::backends::fftw::private::crypto::bootstrap::FourierBootstrapKey;
use crate::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, FftwStandardGlweRelinearizationKey32, FftwStandardGlweRelinearizationKey64, GlweSecretKey32, GlweSecretKey64, GlweSecretKeyEntity, Variance};
use crate::specification::engines::{
    GlweRelinearizationKeyCreationEngine, GlweRelinearizationKeyCreationError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

/// # Description:
/// Implementation of [`GlweRelinearizationKeyCreationEngine`] for [`FftwEngine`] that operates on
/// 32 bits integers. It creates a relinearization key based on an input GLWE secret key.
impl GlweRelinearizationKeyCreationEngine<GlweSecretKey32, FftwStandardGlweRelinearizationKey32>
for FftwEngine
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
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_sk: GlweSecretKey32 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let rlk: FftwStandardGlweRelinearizationKey32 =
    ///     fftw_engine.create_glwe_relinearization_key(&glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// #
    /// assert_eq!(rlk.glwe_dimension(), glwe_dim);
    /// assert_eq!(rlk.polynomial_size(), poly_size);
    /// assert_eq!(rlk.decomposition_base_log(), dec_bl);
    /// assert_eq!(rlk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(glwe_sk)?;
    /// fftw_engine.destroy(rlk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_relinearization_key(
        &mut self,
        input: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<FftwStandardGlweRelinearizationKey32, GlweRelinearizationKeyCreationError<Self::EngineError>>
    {
        Ok(unsafe { self.create_glwe_relinearization_key_unchecked(input, decomposition_base_log,
                                                                   decomposition_level_count, noise
        ) })
    }

    unsafe fn create_glwe_relinearization_key_unchecked(
        &mut self,
        input: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> FftwStandardGlweRelinearizationKey32 {
        let mut rlk = StandardGlweRelinearizationKey::allocate(
            0_u32,
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
        );
        let buffers = self.get_fourier_u32_buffer(
            rlk.polynomial_size(),
            rlk.glwe_size(),
        );
        rlk.fill_with_new_key(
            input,
            noise,
            &mut self.encryption_generator,
            buffers,
        );
        FftwStandardGlweRelinearizationKey32(rlk)
    }
}

/// # Description:
/// Implementation of [`GlweRelinearizationKeyCreationEngine`] for [`FftwEngine`] that operates on
/// 64 bits integers. It creates a relinearization key based on an input GLWE secret key.
impl GlweRelinearizationKeyCreationEngine<GlweSecretKey64, FftwStandardGlweRelinearizationKey64>
for FftwEngine
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
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_sk: GlweSecretKey64 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let rlk: FftwStandardGlweRelinearizationKey64 =
    ///     fftw_engine.create_glwe_relinearization_key(&glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// #
    /// assert_eq!(rlk.glwe_dimension(), glwe_dim);
    /// assert_eq!(rlk.polynomial_size(), poly_size);
    /// assert_eq!(rlk.decomposition_base_log(), dec_bl);
    /// assert_eq!(rlk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(glwe_sk)?;
    /// fftw_engine.destroy(rlk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_relinearization_key(
        &mut self,
        input: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<FftwStandardGlweRelinearizationKey64, GlweRelinearizationKeyCreationError<Self::EngineError>>
    {
        Ok(unsafe { self.create_glwe_relinearization_key_unchecked(input, decomposition_base_log,
                                                                   decomposition_level_count, noise
        ) })
    }

    unsafe fn create_glwe_relinearization_key_unchecked(
        &mut self,
        input: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> FftwStandardGlweRelinearizationKey64 {
        let mut rlk = StandardGlweRelinearizationKey::allocate(
            0_u64,
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
        );
        let buffers = self.get_fourier_u64_buffer(
            rlk.polynomial_size(),
            rlk.glwe_size(),
        );
        rlk.fill_with_new_key(
            input,
            noise,
            &mut self.encryption_generator,
            buffers,
        );
        FftwStandardGlweRelinearizationKey64(rlk)
    }
}

