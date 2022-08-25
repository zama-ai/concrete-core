use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{FftwFourierGgswCiphertext32, FftwFourierGgswCiphertext64};
use crate::prelude::{GgswCiphertext32, GgswCiphertext64};
use crate::specification::engines::{
    GgswCiphertextDiscardingConversionEngine, GgswCiphertextDiscardingConversionError,
};
use crate::specification::entities::GgswCiphertextEntity;

/// # Description:
/// Implementation of [`GgswCiphertextDiscardingConversionEngine`] for [`FftwEngine`] that operates
/// on 32 bits integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextDiscardingConversionEngine<GgswCiphertext32, FftwFourierGgswCiphertext32>
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key_1: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext = default_engine
    ///     .encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    ///
    /// let mut fourier_ciphertext: FftwFourierGgswCiphertext32 =
    ///     fftw_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// // We're going to re-encrypt and re-convert the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// default_engine.discard_encrypt_scalar_ggsw_ciphertext(
    ///     &key_2,
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    /// )?;
    /// fftw_engine.discard_convert_ggsw_ciphertext(&mut fourier_ciphertext, &ciphertext)?;
    ///
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_ggsw_ciphertext(
        &mut self,
        output: &mut FftwFourierGgswCiphertext32,
        input: &GgswCiphertext32,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>> {
        GgswCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_ggsw_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut FftwFourierGgswCiphertext32,
        input: &GgswCiphertext32,
    ) {
        let buffers = self.get_fourier_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.0.fill_with_forward_fourier(&input.0, buffers);
    }
}

/// # Description:
/// Implementation of [`GgswCiphertextDiscardingConversionEngine`] for [`FftwEngine`] that operates
/// on 64 bits integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextDiscardingConversionEngine<GgswCiphertext64, FftwFourierGgswCiphertext64>
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key_1: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext = default_engine
    ///     .encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    ///
    /// let mut fourier_ciphertext: FftwFourierGgswCiphertext64 =
    ///     fftw_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// // We're going to re-encrypt and re-convert the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// default_engine.discard_encrypt_scalar_ggsw_ciphertext(
    ///     &key_2,
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    /// )?;
    /// fftw_engine.discard_convert_ggsw_ciphertext(&mut fourier_ciphertext, &ciphertext)?;
    ///
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_ggsw_ciphertext(
        &mut self,
        output: &mut FftwFourierGgswCiphertext64,
        input: &GgswCiphertext64,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>> {
        GgswCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_ggsw_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut FftwFourierGgswCiphertext64,
        input: &GgswCiphertext64,
    ) {
        let buffers = self.get_fourier_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.0.fill_with_forward_fourier(&input.0, buffers);
    }
}

/// This blanket implementation allows to convert from a type to itself by just cloning the value.
impl<Ciphertext> GgswCiphertextDiscardingConversionEngine<Ciphertext, Ciphertext> for FftwEngine
where
    Ciphertext: GgswCiphertextEntity + Clone,
{
    fn discard_convert_ggsw_ciphertext(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>> {
        GgswCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_ggsw_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
    ) {
        *output = input.clone();
    }
}
