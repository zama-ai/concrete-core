use crate::backends::ntt::private::math::ALLOWED_POLY_SIZE;
use crate::prelude::{
    GlweCiphertext32, GlweCiphertext64, GlweCiphertextEntity, GlweCiphertextView32,
    GlweCiphertextView64, LweBootstrapKeyEntity, LweCiphertext32, LweCiphertext64,
    LweCiphertextMutView32, LweCiphertextMutView64, LweCiphertextView32, LweCiphertextView64,
    NttEngine, NttError, NttFourierLweBootstrapKey32, NttFourierLweBootstrapKey64,
};
use crate::specification::engines::{
    LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingBootstrapError,
};

impl From<NttError> for LweCiphertextDiscardingBootstrapError<NttError> {
    fn from(err: NttError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`NttEngine`] that operates on
/// 32 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        NttFourierLweBootstrapKey32,
        GlweCiphertext32,
        LweCiphertext32,
        LweCiphertext32,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u32 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: NttFourierLweBootstrapKey32 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)?;
    ///
    /// ntt_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &NttFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&acc.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBootstrapError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &NttFourierLweBootstrapKey32,
    ) {
        let buffers =
            self.get_u32_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`NttEngine`] that operates on
/// 64 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        NttFourierLweBootstrapKey64,
        GlweCiphertext64,
        LweCiphertext64,
        LweCiphertext64,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u64 << 50; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: NttFourierLweBootstrapKey64 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)?;
    ///
    /// ntt_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &NttFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&acc.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBootstrapError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &NttFourierLweBootstrapKey64,
    ) {
        let buffers =
            self.get_u64_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`NttEngine`] that operates on
/// views containing 32 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        NttFourierLweBootstrapKey32,
        GlweCiphertextView32<'_>,
        LweCiphertextView32<'_>,
        LweCiphertextMutView32<'_>,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u32 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: NttFourierLweBootstrapKey32 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    ///
    /// // Get the GlweCiphertext as a View
    /// let raw_glwe = default_engine.consume_retrieve_glwe_ciphertext(acc)?;
    /// let acc: GlweCiphertextView32 =
    ///     default_engine.create_glwe_ciphertext_from(&raw_glwe[..], poly_size)?;
    ///
    /// let mut raw_input_container = vec![0_u32; lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let input: LweCiphertextMutView32 =
    ///     default_engine.create_lwe_ciphertext_from(&mut raw_input_container[..])?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_input = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input = default_engine.create_lwe_ciphertext_from(&raw_input[..])?;
    ///
    /// let mut raw_output_container = vec![0_u32; lwe_sk_output.lwe_dimension().to_lwe_size().0];
    /// let mut output = default_engine.create_lwe_ciphertext_from(&mut raw_output_container[..])?;
    ///
    /// ntt_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        acc: &GlweCiphertextView32<'_>,
        bsk: &NttFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&acc.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBootstrapError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32<'_>,
        input: &LweCiphertextView32<'_>,
        acc: &GlweCiphertextView32<'_>,
        bsk: &NttFourierLweBootstrapKey32,
    ) {
        let buffers =
            self.get_u32_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`NttEngine`] that operates on
/// views containing 64 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        NttFourierLweBootstrapKey64,
        GlweCiphertextView64<'_>,
        LweCiphertextView64<'_>,
        LweCiphertextMutView64<'_>,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u64 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u64 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: NttFourierLweBootstrapKey64 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    ///
    /// // Get the GlweCiphertext as a View
    /// let raw_glwe = default_engine.consume_retrieve_glwe_ciphertext(acc)?;
    /// let acc: GlweCiphertextView64 =
    ///     default_engine.create_glwe_ciphertext_from(&raw_glwe[..], poly_size)?;
    ///
    /// let mut raw_input_container = vec![0_u64; lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let input: LweCiphertextMutView64 =
    ///     default_engine.create_lwe_ciphertext_from(&mut raw_input_container[..])?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_input = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input = default_engine.create_lwe_ciphertext_from(&raw_input[..])?;
    ///
    /// let mut raw_output_container = vec![0_u64; lwe_sk_output.lwe_dimension().to_lwe_size().0];
    /// let mut output = default_engine.create_lwe_ciphertext_from(&mut raw_output_container[..])?;
    ///
    /// ntt_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        acc: &GlweCiphertextView64<'_>,
        bsk: &NttFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&acc.polynomial_size().0) {
            return Err(LweCiphertextDiscardingBootstrapError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64<'_>,
        input: &LweCiphertextView64<'_>,
        acc: &GlweCiphertextView64<'_>,
        bsk: &NttFourierLweBootstrapKey64,
    ) {
        let buffers =
            self.get_u64_buffer(bsk.polynomial_size(), bsk.glwe_dimension().to_glwe_size());
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}
