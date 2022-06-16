use crate::backends::fftw::engines::{FftwEngine, FftwError};
use crate::backends::fftw::entities::{FftwFourierGlweCiphertext32, FftwFourierGlweCiphertext64};
use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::{Complex64, ALLOWED_POLY_SIZE};
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::prelude::{GlweCiphertext32, GlweCiphertext64};
use crate::specification::engines::{
    GlweCiphertextConversionEngine, GlweCiphertextConversionError,
};
use crate::specification::entities::GlweCiphertextEntity;

impl From<FftwError> for GlweCiphertextConversionError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`FftwEngine`] that operates on
/// 32 bits integers. It converts a GLWE ciphertext from the standard to the Fourier domain.
impl GlweCiphertextConversionEngine<GlweCiphertext32, FftwFourierGlweCiphertext32> for FftwEngine {
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
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(ciphertext)?;
    /// fftw_engine.destroy(fourier_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext32,
    ) -> Result<FftwFourierGlweCiphertext32, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext32,
    ) -> FftwFourierGlweCiphertext32 {
        let mut output = FourierGlweCiphertext::allocate(
            Complex64::new(0., 0.),
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let buffers = self.get_fourier_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.fill_with_forward_fourier(&input.0, buffers);
        FftwFourierGlweCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`FftwEngine`] that operates on
/// 64 bits integers. It converts a GLWE ciphertext from the standard to the Fourier domain.
impl GlweCiphertextConversionEngine<GlweCiphertext64, FftwFourierGlweCiphertext64> for FftwEngine {
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
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// assert_eq!(fourier_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(fourier_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(ciphertext)?;
    /// fftw_engine.destroy(fourier_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext64,
    ) -> Result<FftwFourierGlweCiphertext64, GlweCiphertextConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext64,
    ) -> FftwFourierGlweCiphertext64 {
        let mut output = FourierGlweCiphertext::allocate(
            Complex64::new(0., 0.),
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let buffers = self.get_fourier_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        output.fill_with_forward_fourier(&input.0, buffers);
        FftwFourierGlweCiphertext64(output)
    }
}

/// This blanket implementation allows to convert from a type to itself by just cloning the value.
impl<Ciphertext> GlweCiphertextConversionEngine<Ciphertext, Ciphertext> for FftwEngine
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
/// Implementation of [`GlweCiphertextConversionEngine`] for [`FftwEngine`] that operates on
/// 32 bits integers. It converts a GLWE ciphertext from the Fourier to the standard domain.
impl GlweCiphertextConversionEngine<FftwFourierGlweCiphertext32, GlweCiphertext32> for FftwEngine {
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
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// // Then we convert it back to the standard domain.
    /// let ciphertext_out: GlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&fourier_ciphertext)?;
    ///
    /// assert_eq!(ciphertext_out.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_out.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(ciphertext)?;
    /// default_engine.destroy(ciphertext_out)?;
    /// fftw_engine.destroy(fourier_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &FftwFourierGlweCiphertext32,
    ) -> Result<GlweCiphertext32, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &FftwFourierGlweCiphertext32,
    ) -> GlweCiphertext32 {
        let mut output = GlweCiphertext::allocate(
            0_u32,
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let buffers = self.get_fourier_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        input
            .0
            .fill_glwe_with_backward_fourier(&mut output, buffers);
        GlweCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextConversionEngine`] for [`FftwEngine`] that operates on
/// 64 bits integers. It converts a GLWE ciphertext from the Fourier to the standard domain.
impl GlweCiphertextConversionEngine<FftwFourierGlweCiphertext64, GlweCiphertext64> for FftwEngine {
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
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    /// #
    /// // Then we convert it back to the standard domain.
    /// let ciphertext_out: GlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&fourier_ciphertext)?;
    ///
    /// assert_eq!(ciphertext_out.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_out.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector)?;
    /// default_engine.destroy(ciphertext)?;
    /// default_engine.destroy(ciphertext_out)?;
    /// fftw_engine.destroy(fourier_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &FftwFourierGlweCiphertext64,
    ) -> Result<GlweCiphertext64, GlweCiphertextConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweCiphertextConversionError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &FftwFourierGlweCiphertext64,
    ) -> GlweCiphertext64 {
        let mut output = GlweCiphertext::allocate(
            0_u64,
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let buffers = self.get_fourier_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        input
            .0
            .fill_glwe_with_backward_fourier(&mut output, buffers);
        GlweCiphertext64(output)
    }
}
