use crate::backends::ntt::private::math::ALLOWED_POLY_SIZE;
use crate::prelude::{
    GgswCiphertextEntity, GlweCiphertext32, GlweCiphertext64, NttEngine, NttError,
    NttFourierGgswCiphertext32, NttFourierGgswCiphertext64,
};
use crate::specification::engines::{
    GlweCiphertextsGgswCiphertextFusingCmuxEngine, GlweCiphertextsGgswCiphertextFusingCmuxError,
};
use crate::specification::entities::GlweCiphertextEntity;

impl From<NttError> for GlweCiphertextsGgswCiphertextFusingCmuxError<NttError> {
    fn from(err: NttError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextsGgswCiphertextFusingCmuxEngine`] for [`NttEngine`] that
/// operates on 32 bit integers
impl
    GlweCiphertextsGgswCiphertextFusingCmuxEngine<
        GlweCiphertext32,
        GlweCiphertext32,
        NttFourierGgswCiphertext32,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purposes, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 buts)
    /// let input_ggsw = 1_u32 << 20;
    /// let output_glwe = vec![1_u32 << 20; polynomial_size.0];
    /// let input_glwe = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_output_glwe = default_engine.create_plaintext_vector_from(&output_glwe)?;
    /// let plaintext_input_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let ntt_ggsw: NttFourierGgswCiphertext32 = ntt_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let mut glwe_output =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_output_glwe, noise)?;
    /// let mut glwe_input =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_input_glwe, noise)?;
    ///
    /// // Compute the cmux.
    /// ntt_engine.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
    ///     &mut glwe_output,
    ///     &mut glwe_input,
    ///     &ntt_ggsw,
    /// )?;
    /// #
    /// assert_eq!(glwe_output.polynomial_size(), glwe_input.polynomial_size(),);
    /// assert_eq!(glwe_output.glwe_dimension(), glwe_input.glwe_dimension(),);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
        &mut self,
        glwe_output: &mut GlweCiphertext32,
        glwe_input: &mut GlweCiphertext32,
        ggsw_input: &NttFourierGgswCiphertext32,
    ) -> Result<(), GlweCiphertextsGgswCiphertextFusingCmuxError<Self::EngineError>> {
        GlweCiphertextsGgswCiphertextFusingCmuxError::perform_generic_checks(
            glwe_output,
            glwe_input,
            ggsw_input,
        )?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextsGgswCiphertextFusingCmuxError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        unsafe {
            self.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
                glwe_output,
                glwe_input,
                ggsw_input,
            )
        };
        Ok(())
    }

    unsafe fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_output: &mut GlweCiphertext32,
        glwe_input: &mut GlweCiphertext32,
        ggsw_input: &NttFourierGgswCiphertext32,
    ) {
        let buffers = self.get_u32_buffer(
            ggsw_input.polynomial_size(),
            ggsw_input.glwe_dimension().to_glwe_size(),
        );

        ggsw_input.0.cmux(
            &mut glwe_output.0,
            &mut glwe_input.0,
            &mut buffers.rounded_buffer,
            &mut buffers.ntt,
        );
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextsGgswCiphertextFusingCmuxEngine`] for [`NttEngine`] that
/// operates on 64 bit integers
impl
    GlweCiphertextsGgswCiphertextFusingCmuxEngine<
        GlweCiphertext64,
        GlweCiphertext64,
        NttFourierGgswCiphertext64,
    > for NttEngine
{
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purposes, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 buts)
    /// let input_ggsw = 1_u64 << 50;
    /// let output_glwe = vec![1_u64 << 50; polynomial_size.0];
    /// let input_glwe = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_ggsw = default_engine.create_plaintext_from(&input_ggsw)?;
    /// let plaintext_output_glwe = default_engine.create_plaintext_vector_from(&output_glwe)?;
    /// let plaintext_input_glwe = default_engine.create_plaintext_vector_from(&input_glwe)?;
    ///
    /// let ggsw = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &key,
    ///     &plaintext_ggsw,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    /// let ntt_ggsw: NttFourierGgswCiphertext64 = ntt_engine.convert_ggsw_ciphertext(&ggsw)?;
    /// let mut glwe_output =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_output_glwe, noise)?;
    /// let mut glwe_input =
    ///     default_engine.encrypt_glwe_ciphertext(&key, &plaintext_input_glwe, noise)?;
    ///
    /// // Compute the cmux.
    /// ntt_engine.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
    ///     &mut glwe_output,
    ///     &mut glwe_input,
    ///     &ntt_ggsw,
    /// )?;
    /// #
    /// assert_eq!(glwe_output.polynomial_size(), glwe_input.polynomial_size(),);
    /// assert_eq!(glwe_output.glwe_dimension(), glwe_input.glwe_dimension(),);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext(
        &mut self,
        glwe_output: &mut GlweCiphertext64,
        glwe_input: &mut GlweCiphertext64,
        ggsw_input: &NttFourierGgswCiphertext64,
    ) -> Result<(), GlweCiphertextsGgswCiphertextFusingCmuxError<Self::EngineError>> {
        GlweCiphertextsGgswCiphertextFusingCmuxError::perform_generic_checks(
            glwe_output,
            glwe_input,
            ggsw_input,
        )?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextsGgswCiphertextFusingCmuxError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }
        unsafe {
            self.fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
                glwe_output,
                glwe_input,
                ggsw_input,
            )
        };
        Ok(())
    }

    unsafe fn fuse_cmux_glwe_ciphertexts_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_output: &mut GlweCiphertext64,
        glwe_input: &mut GlweCiphertext64,
        ggsw_input: &NttFourierGgswCiphertext64,
    ) {
        let buffers = self.get_u64_buffer(
            ggsw_input.polynomial_size(),
            ggsw_input.glwe_dimension().to_glwe_size(),
        );

        ggsw_input.0.cmux(
            &mut glwe_output.0,
            &mut glwe_input.0,
            &mut buffers.rounded_buffer,
            &mut buffers.ntt,
        );
    }
}
