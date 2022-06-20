use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{FftwFourierGlweCiphertext32, FftwFourierGlweCiphertext64};
use crate::backends::fftw::private::math::fft::ALLOWED_POLY_SIZE;
use crate::prelude::{
    FftwError, FftwFourierGlweTensorProductCiphertext32, FftwFourierGlweTensorProductCiphertext64,
    GlweCiphertext32, GlweCiphertext64, GlweCiphertextConversionEngine, GlweCiphertextEntity,
    GlweCiphertextTensorProductSameKeyEngine, GlweCiphertextTensorProductSameKeyError,
    ScalingFactor,
};

impl From<FftwError> for GlweCiphertextTensorProductSameKeyError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextTensorProductSameKeyEngine`] for [`FftwEngine`] that operates
/// on 32-bit integer GLWE Ciphertexts.
impl
    GlweCiphertextTensorProductSameKeyEngine<
        GlweCiphertext32,
        GlweCiphertext32,
        FftwFourierGlweTensorProductCiphertext32,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = vec![3_u32 << 20; 256];
    /// let input_2 = vec![4_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// let scale = ScalingFactor(2_u64 << 19);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_1, noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_2, noise)?;
    ///
    /// // Compute the tensor product between the ciphertexts
    /// // The result is in the Fourier domain
    /// let tensor_product_ciphertext =
    ///     fftw_engine.tensor_product_glwe_ciphertext_same_key(&ciphertext_1, &ciphertext_2, scale)?;
    ///
    /// assert_eq!(
    ///     tensor_product_ciphertext.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(tensor_product_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &GlweCiphertext32,
        input2: &GlweCiphertext32,
        scale: ScalingFactor,
    ) -> Result<
        FftwFourierGlweTensorProductCiphertext32,
        GlweCiphertextTensorProductSameKeyError<Self::EngineError>,
    > {
        GlweCiphertextTensorProductSameKeyError::perform_generic_checks(input1, input2, scale)?;
        if !ALLOWED_POLY_SIZE.contains(&input1.polynomial_size().0) {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u32::MAX as u64 {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.tensor_product_glwe_ciphertext_same_key_unchecked(input1, input2, scale)
            },
        )
    }

    unsafe fn tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &GlweCiphertext32,
        input2: &GlweCiphertext32,
        scale: ScalingFactor,
    ) -> FftwFourierGlweTensorProductCiphertext32 {
        let fourier1: FftwFourierGlweCiphertext32 = self.convert_glwe_ciphertext(input1).unwrap();
        let fourier2: FftwFourierGlweCiphertext32 = self.convert_glwe_ciphertext(input2).unwrap();
        FftwFourierGlweTensorProductCiphertext32(
            fourier1.0.tensor_product_same_key(&fourier2.0, scale),
        )
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextTensorProductSameKeyEngine`] for [`FftwEngine`] that operates
/// on 64-bit integer GLWE Ciphertexts in the Fourier domain.
impl
    GlweCiphertextTensorProductSameKeyEngine<
        GlweCiphertext64,
        GlweCiphertext64,
        FftwFourierGlweTensorProductCiphertext64,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = vec![3_u64 << 50; 256];
    /// let input_2 = vec![4_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// let scale = ScalingFactor(2_u64 << 49);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_1, noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_2, noise)?;
    ///
    /// // Compute the tensor product between the ciphertexts
    /// let tensor_product_ciphertext =
    ///     fftw_engine.tensor_product_glwe_ciphertext_same_key(&ciphertext_1, &ciphertext_2, scale)?;
    ///
    /// assert_eq!(
    ///     tensor_product_ciphertext.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(tensor_product_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &GlweCiphertext64,
        input2: &GlweCiphertext64,
        scale: ScalingFactor,
    ) -> Result<
        FftwFourierGlweTensorProductCiphertext64,
        GlweCiphertextTensorProductSameKeyError<Self::EngineError>,
    > {
        GlweCiphertextTensorProductSameKeyError::perform_generic_checks(input1, input2, scale)?;
        if !ALLOWED_POLY_SIZE.contains(&input1.polynomial_size().0) {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 == u64::MAX {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.tensor_product_glwe_ciphertext_same_key_unchecked(input1, input2, scale)
            },
        )
    }

    unsafe fn tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &GlweCiphertext64,
        input2: &GlweCiphertext64,
        scale: ScalingFactor,
    ) -> FftwFourierGlweTensorProductCiphertext64 {
        let fourier1: FftwFourierGlweCiphertext64 = self.convert_glwe_ciphertext(input1).unwrap();
        let fourier2: FftwFourierGlweCiphertext64 = self.convert_glwe_ciphertext(input2).unwrap();
        FftwFourierGlweTensorProductCiphertext64(
            fourier1.0.tensor_product_same_key(&fourier2.0, scale),
        )
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextTensorProductSameKeyEngine`] for [`FftwEngine`] that operates
/// on 32-bit integer GLWE Ciphertexts in the Fourier domain.
impl
    GlweCiphertextTensorProductSameKeyEngine<
        FftwFourierGlweCiphertext32,
        FftwFourierGlweCiphertext32,
        FftwFourierGlweTensorProductCiphertext32,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = vec![3_u32 << 20; 256];
    /// let input_2 = vec![4_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// let scale = ScalingFactor(2_u64 << 19);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_1, noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_2, noise)?;
    ///
    /// // Then we convert them to the Fourier domain.
    /// let fourier_ciphertext_1: FftwFourierGlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext_1)?;
    /// let fourier_ciphertext_2: FftwFourierGlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext_2)?;
    /// // Compute the tensor product between the ciphertexts
    /// // The result is in the Fourier domain
    /// let tensor_product_ciphertext = fftw_engine.tensor_product_glwe_ciphertext_same_key(
    ///     &fourier_ciphertext_1,
    ///     &fourier_ciphertext_2,
    ///     scale,
    /// )?;
    ///
    /// assert_eq!(
    ///     tensor_product_ciphertext.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(fourier_ciphertext_1)?;
    /// fftw_engine.destroy(fourier_ciphertext_2)?;
    /// fftw_engine.destroy(tensor_product_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &FftwFourierGlweCiphertext32,
        input2: &FftwFourierGlweCiphertext32,
        scale: ScalingFactor,
    ) -> Result<
        FftwFourierGlweTensorProductCiphertext32,
        GlweCiphertextTensorProductSameKeyError<Self::EngineError>,
    > {
        GlweCiphertextTensorProductSameKeyError::perform_generic_checks(input1, input2, scale)?;
        if !ALLOWED_POLY_SIZE.contains(&input1.polynomial_size().0) {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u32::MAX as u64 {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.tensor_product_glwe_ciphertext_same_key_unchecked(input1, input2, scale)
            },
        )
    }

    unsafe fn tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &FftwFourierGlweCiphertext32,
        input2: &FftwFourierGlweCiphertext32,
        scale: ScalingFactor,
    ) -> FftwFourierGlweTensorProductCiphertext32 {
        FftwFourierGlweTensorProductCiphertext32(input1.0.tensor_product_same_key(&input2.0, scale))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextTensorProductSameKeyEngine`] for [`FftwEngine`] that operates
/// on 64-bit integer GLWE Ciphertexts in the Fourier domain.
impl
    GlweCiphertextTensorProductSameKeyEngine<
        FftwFourierGlweCiphertext64,
        FftwFourierGlweCiphertext64,
        FftwFourierGlweTensorProductCiphertext64,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = vec![3_u64 << 50; 256];
    /// let input_2 = vec![4_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// let scale = ScalingFactor(2_u64 << 49);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_1, noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector_2, noise)?;
    ///
    /// // Then we convert them to the Fourier domain.
    /// let fourier_ciphertext_1: FftwFourierGlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext_1)?;
    /// let fourier_ciphertext_2: FftwFourierGlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext_2)?;
    /// // Compute the tensor product between the ciphertexts
    /// let tensor_product_ciphertext = fftw_engine.tensor_product_glwe_ciphertext_same_key(
    ///     &fourier_ciphertext_1,
    ///     &fourier_ciphertext_2,
    ///     scale,
    /// )?;
    ///
    /// assert_eq!(
    ///     tensor_product_ciphertext.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(fourier_ciphertext_1)?;
    /// fftw_engine.destroy(fourier_ciphertext_2)?;
    /// fftw_engine.destroy(tensor_product_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn tensor_product_glwe_ciphertext_same_key(
        &mut self,
        input1: &FftwFourierGlweCiphertext64,
        input2: &FftwFourierGlweCiphertext64,
        scale: ScalingFactor,
    ) -> Result<
        FftwFourierGlweTensorProductCiphertext64,
        GlweCiphertextTensorProductSameKeyError<Self::EngineError>,
    > {
        GlweCiphertextTensorProductSameKeyError::perform_generic_checks(input1, input2, scale)?;
        if !ALLOWED_POLY_SIZE.contains(&input1.polynomial_size().0) {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 == u64::MAX {
            return Err(GlweCiphertextTensorProductSameKeyError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.tensor_product_glwe_ciphertext_same_key_unchecked(input1, input2, scale)
            },
        )
    }

    unsafe fn tensor_product_glwe_ciphertext_same_key_unchecked(
        &mut self,
        input1: &FftwFourierGlweCiphertext64,
        input2: &FftwFourierGlweCiphertext64,
        scale: ScalingFactor,
    ) -> FftwFourierGlweTensorProductCiphertext64 {
        FftwFourierGlweTensorProductCiphertext64(input1.0.tensor_product_same_key(&input2.0, scale))
    }
}
