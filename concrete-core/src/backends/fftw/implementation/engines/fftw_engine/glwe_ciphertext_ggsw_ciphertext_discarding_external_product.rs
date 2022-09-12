use crate::prelude::{
    FftwEngine, FftwError, FftwFourierGgswCiphertext32, FftwFourierGgswCiphertext64,
    GgswCiphertextEntity, GlweCiphertext32, GlweCiphertext64, GlweCiphertextEntity,
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine,
    GlweCiphertextGgswCiphertextDiscardingExternalProductError,
};

impl From<FftwError> for GlweCiphertextGgswCiphertextDiscardingExternalProductError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextGgswCiphertextDiscardingExternalProductEngine`] for
/// [`FftwEngine`] that operates on 32 bits integers.
impl
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine<
        GlweCiphertext32,
        FftwFourierGgswCiphertext32,
        GlweCiphertext32,
    > for FftwEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_ggsw = 3_u32 << 20;
    /// let input_glwe = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_glwe = default_engine.create_plaintext_array_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftwFourierGgswCiphertext32 = fftw_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let glwe = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_glwe, noise)?;
    ///
    /// // We allocate an output ciphertext simply by cloning the input.
    /// // The content of this output ciphertext will by wiped by the external product.
    /// let mut product = glwe.clone();
    /// fftw_engine.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
    ///     &glwe,
    ///     &complex_ggsw,
    ///     &mut product,
    /// )?;
    /// #
    /// # assert_eq!(
    /// #     product.polynomial_size(),
    /// #     glwe.polynomial_size(),
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
        &mut self,
        glwe_input: &GlweCiphertext32,
        ggsw_input: &FftwFourierGgswCiphertext32,
        output: &mut GlweCiphertext32,
    ) -> Result<(), GlweCiphertextGgswCiphertextDiscardingExternalProductError<Self::EngineError>>
    {
        FftwError::perform_fftw_checks(glwe_input.polynomial_size())?;
        GlweCiphertextGgswCiphertextDiscardingExternalProductError::perform_generic_checks(
            glwe_input, ggsw_input, output,
        )?;
        unsafe {
            self.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
                glwe_input, ggsw_input, output,
            )
        };
        Ok(())
    }

    unsafe fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_input: &GlweCiphertext32,
        ggsw_input: &FftwFourierGgswCiphertext32,
        output: &mut GlweCiphertext32,
    ) {
        let buffers = self.get_fourier_u32_buffer(
            ggsw_input.polynomial_size(),
            ggsw_input.glwe_dimension().to_glwe_size(),
        );
        ggsw_input.0.external_product(
            &mut output.0,
            &glwe_input.0,
            &mut buffers.fft_buffers,
            &mut buffers.rounded_buffer,
        );
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextGgswCiphertextDiscardingExternalProductEngine`] for
/// [`FftwEngine`] that operates on 64 bits integers.
impl
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine<
        GlweCiphertext64,
        FftwFourierGgswCiphertext64,
        GlweCiphertext64,
    > for FftwEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_ggsw = 3_u64 << 50;
    /// let input_glwe = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_glwe = default_engine.create_plaintext_array_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let complex_ggsw: FftwFourierGgswCiphertext64 = fftw_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let glwe = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_glwe, noise)?;
    ///
    /// // We allocate an output ciphertext simply by cloning the input.
    /// // The content of this output ciphertext will by wiped by the external product.
    /// let mut product = glwe.clone();
    /// fftw_engine.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
    ///     &glwe,
    ///     &complex_ggsw,
    ///     &mut product,
    /// )?;
    /// #
    /// # assert_eq!(
    /// #     product.polynomial_size(),
    /// #     glwe.polynomial_size(),
    /// # );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
        &mut self,
        glwe_input: &GlweCiphertext64,
        ggsw_input: &FftwFourierGgswCiphertext64,
        output: &mut GlweCiphertext64,
    ) -> Result<(), GlweCiphertextGgswCiphertextDiscardingExternalProductError<Self::EngineError>>
    {
        FftwError::perform_fftw_checks(glwe_input.polynomial_size())?;
        GlweCiphertextGgswCiphertextDiscardingExternalProductError::perform_generic_checks(
            glwe_input, ggsw_input, output,
        )?;
        unsafe {
            self.discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
                glwe_input, ggsw_input, output,
            )
        }
        Ok(())
    }

    unsafe fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_input: &GlweCiphertext64,
        ggsw_input: &FftwFourierGgswCiphertext64,
        output: &mut GlweCiphertext64,
    ) {
        let buffers = self.get_fourier_u64_buffer(
            ggsw_input.polynomial_size(),
            ggsw_input.glwe_dimension().to_glwe_size(),
        );
        ggsw_input.0.external_product(
            &mut output.0,
            &glwe_input.0,
            &mut buffers.fft_buffers,
            &mut buffers.rounded_buffer,
        );
    }
}
