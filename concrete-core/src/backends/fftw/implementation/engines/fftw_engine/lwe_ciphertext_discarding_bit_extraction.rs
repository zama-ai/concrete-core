use crate::backends::fftw::engines::{FftwEngine, FftwError};
use crate::backends::fftw::entities::{FftwFourierLweBootstrapKey32, FftwFourierLweBootstrapKey64};
use crate::backends::fftw::private::crypto::wop_pbs::extract_bits;
use crate::backends::fftw::private::math::fft::ALLOWED_POLY_SIZE;
use crate::prelude::{
    CiphertextModulusLog, DeltaLog, ExtractedBitsCount, LweBootstrapKeyEntity, LweCiphertext32,
    LweCiphertext64, LweCiphertextVector32, LweCiphertextVector64, LweKeyswitchKey32,
    LweKeyswitchKey64,
};
use crate::specification::engines::{
    LweCiphertextDiscardingBitExtractEngine, LweCiphertextDiscardingBitExtractError,
};

impl From<FftwError> for LweCiphertextDiscardingBitExtractError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftwEngine`] that operates
/// on 32 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftwFourierLweBootstrapKey32,
        LweKeyswitchKey32,
        LweCiphertext32,
        LweCiphertextVector32,
    > for FftwEngine
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
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey32 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey32 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey32 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftwFourierLweBootstrapKey32 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&input_lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &output_lwe_sk,
    ///     noise,
    ///     LweCiphertextCount(extracted_bits_count.0),
    /// )?;
    ///
    /// fftw_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertext32,
        bsk: &FftwFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&bsk.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBitExtractError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(32),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVector32,
        input: &LweCiphertext32,
        bsk: &FftwFourierLweBootstrapKey32,
        ksk: &LweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let buffers =
            self.get_fourier_u32_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        extract_bits(
            delta_log,
            &mut output.0,
            &input.0,
            &ksk.0,
            &bsk.0,
            buffers,
            extracted_bits_count,
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBitExtractEngine`] for [`FftwEngine`] that operates
/// on 64 bits integers.
impl
    LweCiphertextDiscardingBitExtractEngine<
        FftwFourierLweBootstrapKey64,
        LweKeyswitchKey64,
        LweCiphertext64,
        LweCiphertextVector64,
    > for FftwEngine
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
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u64 << 50;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(1), PolynomialSize(512));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let extracted_bits_count = ExtractedBitsCount(1);
    /// let delta_log = DeltaLog(5);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let large_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, and rely on /dev/random only for tests.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let input_lwe_sk: LweSecretKey64 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    /// let output_lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let bsk: LweBootstrapKey64 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &output_lwe_sk,
    ///     &glwe_sk,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// let ksk: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_lwe_sk,
    ///     &output_lwe_sk,
    ///     dec_lc,
    ///     dec_bl,
    ///     noise,
    /// )?;
    /// let bsk: FftwFourierLweBootstrapKey64 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&input_lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &output_lwe_sk,
    ///     noise,
    ///     LweCiphertextCount(extracted_bits_count.0),
    /// )?;
    ///
    /// fftw_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut output,
    ///     &input,
    ///     &bsk,
    ///     &ksk,
    ///     extracted_bits_count,
    ///     delta_log,
    /// )?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim);
    /// assert_eq!(
    ///     output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(extracted_bits_count.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertext64,
        bsk: &FftwFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&bsk.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBitExtractError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(64),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertext64,
        bsk: &FftwFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let buffers =
            self.get_fourier_u64_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        extract_bits(
            delta_log,
            &mut output.0,
            &input.0,
            &ksk.0,
            &bsk.0,
            buffers,
            extracted_bits_count,
        );
    }
}
