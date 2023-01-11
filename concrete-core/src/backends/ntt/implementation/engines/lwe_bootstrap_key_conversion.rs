use crate::backends::ntt::private::crypto::bootstrap::ntt::NttBootstrapKey;
use crate::prelude::{
    LweBootstrapKey32, LweBootstrapKey64, NttEngine, NttFourierLweBootstrapKey32,
    NttFourierLweBootstrapKey64,
};
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

/// # Description:
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`NttEngine`] that operates on
/// 32 bits integers. It converts a bootstrap key from the standard to the NTT domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey32, NttFourierLweBootstrapKey32> for NttEngine {
    /// # Example
    /// ```
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
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: NttFourierLweBootstrapKey32 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> Result<NttFourierLweBootstrapKey32, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> NttFourierLweBootstrapKey32 {
        let output = NttBootstrapKey::allocate(
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        let mut output_bsk = NttFourierLweBootstrapKey32(output);
        // let ntt = self.ntts32.get_mut(&input.polynomial_size()).unwrap();
        let buffers = self.get_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output_bsk
            .0
            .fill_with_forward_ntt(&input.0, &mut buffers.ntt);
        output_bsk
    }
}

/// # Description:
/// Implementation of [`LweBootstrapKeyConversionEngine`] for [`NttEngine`] that operates on
/// 64 bits integers. It converts a bootstrap key from the standard to the NTT domain.
impl LweBootstrapKeyConversionEngine<LweBootstrapKey64, NttFourierLweBootstrapKey64> for NttEngine {
    /// # Example
    /// ```
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
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: NttFourierLweBootstrapKey64 = ntt_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// #
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> Result<NttFourierLweBootstrapKey64, LweBootstrapKeyConversionError<Self::EngineError>>
    {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> NttFourierLweBootstrapKey64 {
        let output = NttBootstrapKey::allocate(
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        let mut output_bsk = NttFourierLweBootstrapKey64(output);
        // let ntt = self.ntts64.get_mut(&input.polynomial_size()).unwrap();
        let buffers = self.get_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output_bsk
            .0
            .fill_with_forward_ntt(&input.0, &mut buffers.ntt);
        output_bsk
    }
}

impl<Key> LweBootstrapKeyConversionEngine<Key, Key> for NttEngine
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
