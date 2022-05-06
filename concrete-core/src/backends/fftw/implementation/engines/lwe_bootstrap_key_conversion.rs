use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{FftwFourierLweBootstrapKey32, FftwFourierLweBootstrapKey64};
use crate::backends::fftw::private::crypto::bootstrap::FourierBootstrapKey;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::prelude::{LweBootstrapKey32, LweBootstrapKey64};
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

/// # Description:
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`FftwEngine`] that operates on
/// 32 bits integers. It converts a bootstrap key from the standard to the Fourier domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey32, FftwFourierLweBootstrapKey32>
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
    /// let lwe_sk: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftwFourierLweBootstrapKey32 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// fftw_engine.destroy(fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> Result<FftwFourierLweBootstrapKey32, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> FftwFourierLweBootstrapKey32 {
        let output = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        let mut output_bsk = FftwFourierLweBootstrapKey32(output);
        let buffers = self.get_fourier_u32_buffer(
            output_bsk.polynomial_size(),
            output_bsk.glwe_dimension().to_glwe_size(),
        );
        output_bsk.0.fill_with_forward_fourier(&input.0, buffers);
        output_bsk
    }
}

/// # Description:
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`FftwEngine`] that operates on
/// 64 bits integers. It converts a bootstrap key from the standard to the Fourier domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey64, FftwFourierLweBootstrapKey64>
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
    /// let lwe_sk: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftwFourierLweBootstrapKey64 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// default_engine.destroy(lwe_sk)?;
    /// default_engine.destroy(glwe_sk)?;
    /// default_engine.destroy(bsk)?;
    /// fftw_engine.destroy(fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> Result<FftwFourierLweBootstrapKey64, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> FftwFourierLweBootstrapKey64 {
        let output = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        let mut output_bsk = FftwFourierLweBootstrapKey64(output);
        let buffers = self.get_fourier_u64_buffer(
            output_bsk.polynomial_size(),
            output_bsk.glwe_dimension().to_glwe_size(),
        );
        output_bsk.0.fill_with_forward_fourier(&input.0, buffers);
        output_bsk
    }
}

impl<Key> LweBootstrapKeyConversionEngine<Key, Key> for FftwEngine
where
    Key: LweBootstrapKeyEntity + Clone,
{
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &Key,
    ) -> Result<Key, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &Key) -> Key {
        (*input).clone()
    }
}
