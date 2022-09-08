use super::super::super::private::crypto::ggsw::{
    fill_with_forward_fourier_scratch, FourierGgswCiphertext, StandardGgswCiphertextView,
};
use super::super::super::private::math::fft::Fft;
use super::super::entities::{FftFourierGgswCiphertext32, FftFourierGgswCiphertext64};
use super::{FftEngine, FftError};
use crate::commons::math::tensor::AsRefSlice;
use crate::prelude::{
    GgswCiphertext32, GgswCiphertext64, GgswCiphertextConversionError,
    GgswCiphertextDiscardingConversionEngine, GgswCiphertextDiscardingConversionError,
};
use crate::specification::engines::GgswCiphertextConversionEngine;
use crate::specification::entities::GgswCiphertextEntity;
use aligned_vec::avec;
use concrete_fft::c64;

impl From<FftError> for GgswCiphertextDiscardingConversionError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}
impl From<FftError> for GgswCiphertextConversionError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextDiscardingConversionEngine`] for [`FftEngine`] that
/// operates on 32 bit integers. It converts a GGSW ciphertext from the standard to the Fourier
/// domain.
impl GgswCiphertextDiscardingConversionEngine<GgswCiphertext32, FftFourierGgswCiphertext32>
    for FftEngine
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
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key_1: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext = default_engine
    ///     .encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    ///
    /// let mut fourier_ciphertext: FftFourierGgswCiphertext32 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
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
    /// fft_engine.discard_convert_ggsw_ciphertext(&mut fourier_ciphertext, &ciphertext)?;
    ///
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
        output: &mut FftFourierGgswCiphertext32,
        input: &GgswCiphertext32,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>> {
        FftEngine::check_supported_size(input.0.polynomial_size())?;
        GgswCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_ggsw_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut FftFourierGgswCiphertext32,
        input: &GgswCiphertext32,
    ) {
        let fft = Fft::new(input.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            fill_with_forward_fourier_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        output.0.as_mut_view().fill_with_forward_fourier(
            StandardGgswCiphertextView::new(
                input.0.tensor.as_slice(),
                input.polynomial_size(),
                input.glwe_dimension().to_glwe_size(),
                input.decomposition_base_log(),
                input.decomposition_level_count(),
            ),
            fft,
            self.stack(),
        );
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextDiscardingConversionEngine`] for [`FftEngine`] that
/// operates on 64 bit integers. It converts a GGSW ciphertext from the standard to the Fourier
/// domain.
impl GgswCiphertextDiscardingConversionEngine<GgswCiphertext64, FftFourierGgswCiphertext64>
    for FftEngine
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
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key_1: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// let mut ciphertext = default_engine
    ///     .encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    ///
    /// let mut fourier_ciphertext: FftFourierGgswCiphertext64 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
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
    /// fft_engine.discard_convert_ggsw_ciphertext(&mut fourier_ciphertext, &ciphertext)?;
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
        output: &mut FftFourierGgswCiphertext64,
        input: &GgswCiphertext64,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>> {
        FftEngine::check_supported_size(input.0.polynomial_size())?;
        GgswCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_ggsw_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut FftFourierGgswCiphertext64,
        input: &GgswCiphertext64,
    ) {
        let fft = Fft::new(input.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            fill_with_forward_fourier_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        output.0.as_mut_view().fill_with_forward_fourier(
            StandardGgswCiphertextView::new(
                input.0.tensor.as_slice(),
                input.polynomial_size(),
                input.glwe_dimension().to_glwe_size(),
                input.decomposition_base_log(),
                input.decomposition_level_count(),
            ),
            fft,
            self.stack(),
        );
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextConversionEngine`] for [`FftEngine`] that operates on 32
/// bit integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextConversionEngine<GgswCiphertext32, FftFourierGgswCiphertext32> for FftEngine {
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
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext32 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext32,
    ) -> Result<FftFourierGgswCiphertext32, GgswCiphertextConversionError<Self::EngineError>> {
        FftEngine::check_supported_size(input.0.polynomial_size())?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext32,
    ) -> FftFourierGgswCiphertext32 {
        let glwe_size = input.glwe_dimension().to_glwe_size();
        let mut output = FftFourierGgswCiphertext32(FourierGgswCiphertext::new(
            avec![
                c64::default();
                (input.polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * input.decomposition_level_count().0)
                    / 2
            ]
            .into_boxed_slice(),
            input.polynomial_size(),
            glwe_size,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
        ));

        self.discard_convert_ggsw_ciphertext_unchecked(&mut output, input);
        output
    }
}

/// # Description
///
/// Implementation of [`GgswCiphertextConversionEngine`] for [`FftEngine`] that operates on 64
/// bit integers. It converts a GGSW ciphertext from the standard to the Fourier domain.
impl GgswCiphertextConversionEngine<GgswCiphertext64, FftFourierGgswCiphertext64> for FftEngine {
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
    /// let mut fft_engine = FftEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftFourierGgswCiphertext64 =
    ///     fft_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(fourier_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(fourier_ciphertext.decomposition_level_count(), level);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext64,
    ) -> Result<FftFourierGgswCiphertext64, GgswCiphertextConversionError<Self::EngineError>> {
        FftEngine::check_supported_size(input.0.polynomial_size())?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext64,
    ) -> FftFourierGgswCiphertext64 {
        let glwe_size = input.glwe_dimension().to_glwe_size();
        let mut output = FftFourierGgswCiphertext64(FourierGgswCiphertext::new(
            avec![
                c64::default();
                (input.polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * input.decomposition_level_count().0)
                    / 2
            ]
            .into_boxed_slice(),
            input.polynomial_size(),
            glwe_size,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
        ));

        self.discard_convert_ggsw_ciphertext_unchecked(&mut output, input);
        output
    }
}
