use crate::backends::ntt::engines::{NttEngine, NttError};
use crate::backends::ntt::entities::{NttFourierGlweCiphertext32, NttFourierGlweCiphertext64};
use crate::backends::ntt::private::crypto::glwe::NttGlweCiphertext;
use crate::backends::ntt::private::math::ALLOWED_POLY_SIZE;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::prelude::{GlweCiphertext32, GlweCiphertext64};
use crate::specification::engines::{
    GlweCiphertextConversionEngine, GlweCiphertextConversionError,
};
use crate::specification::entities::GlweCiphertextEntity;

impl From<NttError> for GlweCiphertextConversionError<NttError> {
    fn from(err: NttError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`NttEngine`] that operates on
/// 32 bits integers. It converts a GLWE ciphertext from the standard to the NTT domain.
impl GlweCiphertextConversionEngine<GlweCiphertext32, NttFourierGlweCiphertext32> for NttEngine {
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: NttFourierGlweCiphertext32 =
    ///     ntt_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext32,
    ) -> Result<NttFourierGlweCiphertext32, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext32,
    ) -> NttFourierGlweCiphertext32 {
        let buffers = self.get_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let ntt = &mut buffers.ntt;
        let mut output = NttGlweCiphertext::allocate(
            ntt.get_zero_mod_q(),
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.fill_with_forward_fourier(&input.0, ntt);
        NttFourierGlweCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`NttEngine`] that operates on
/// 64 bits integers. It converts a GLWE ciphertext from the standard to the NTT domain.
impl GlweCiphertextConversionEngine<GlweCiphertext64, NttFourierGlweCiphertext64> for NttEngine {
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: NttFourierGlweCiphertext64 =
    ///     ntt_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext64,
    ) -> Result<NttFourierGlweCiphertext64, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext64,
    ) -> NttFourierGlweCiphertext64 {
        // let ntt = self.ntts64.get_mut(&input.polynomial_size()).unwrap();
        let buffers = self.get_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let ntt = &mut buffers.ntt;
        let mut output = NttGlweCiphertext::allocate(
            ntt.get_zero_mod_q(),
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.fill_with_forward_fourier(&input.0, ntt);
        NttFourierGlweCiphertext64(output)
    }
}

/// This blanket implementation allows to convert from a type to itself by just cloning the value.
impl<Ciphertext> GlweCiphertextConversionEngine<Ciphertext, Ciphertext> for NttEngine
where
    Ciphertext: GlweCiphertextEntity + Clone,
{
    fn convert_glwe_ciphertext(
        &mut self,
        input: &Ciphertext,
    ) -> Result<Ciphertext, GlweCiphertextConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(&mut self, input: &Ciphertext) -> Ciphertext {
        (*input).clone()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`NttEngine`] that operates on
/// 32 bits integers. It converts a GLWE ciphertext from the NTT to the standard domain.
impl GlweCiphertextConversionEngine<NttFourierGlweCiphertext32, GlweCiphertext32> for NttEngine {
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: NttFourierGlweCiphertext32 =
    ///     ntt_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// // Then we convert it back to the standard domain.
    /// let ciphertext_out: GlweCiphertext32 =
    ///     ntt_engine.convert_glwe_ciphertext(&fourier_ciphertext)?;
    ///
    /// assert_eq!(ciphertext_out.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_out.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &NttFourierGlweCiphertext32,
    ) -> Result<GlweCiphertext32, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &NttFourierGlweCiphertext32,
    ) -> GlweCiphertext32 {
        let mut output = GlweCiphertext::allocate(
            0_u32,
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );

        let mut input_ = input.0.clone();
        let buffers = self.get_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        input_.fill_with_backward_fourier(&mut output, &mut buffers.ntt);
        GlweCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`NttEngine`] that operates on
/// 64 bits integers. It converts a GLWE ciphertext from the NTT to the standard domain.
impl GlweCiphertextConversionEngine<NttFourierGlweCiphertext64, GlweCiphertext64> for NttEngine {
    /// # Example
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut ntt_engine = NttEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: NttFourierGlweCiphertext64 =
    ///     ntt_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// // Then we convert it back to the standard domain.
    /// let ciphertext_out: GlweCiphertext64 =
    ///     ntt_engine.convert_glwe_ciphertext(&fourier_ciphertext)?;
    ///
    /// assert_eq!(ciphertext_out.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_out.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &NttFourierGlweCiphertext64,
    ) -> Result<GlweCiphertext64, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                NttError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &NttFourierGlweCiphertext64,
    ) -> GlweCiphertext64 {
        let mut output = GlweCiphertext::allocate(
            0_u64,
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );

        let mut input_ = input.0.clone();
        let buffers = self.get_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        input_.fill_with_backward_fourier(&mut output, &mut buffers.ntt);
        GlweCiphertext64(output)
    }
}
