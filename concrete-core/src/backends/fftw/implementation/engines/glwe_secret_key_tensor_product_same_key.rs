use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::private::crypto::secret::FourierGlweSecretKey as ImplFourierGlweSecretKey;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::prelude::{
    FftwFourierGlweTensorProductSecretKey32, FftwFourierGlweTensorProductSecretKey64,
    GlweDimension, GlweSecretKey32, GlweSecretKey64, GlweSecretKeyEntity,
    GlweSecretKeyTensorProductSameKeyEngine, GlweSecretKeyTensorProductSameKeyError,
};

/// # Description:
/// Implementation of [`GlweSecretKeyTensorProductSameKeyEngine`] for
/// [`FftwEngine`] that operates on 32 bits integers. It outputs a tensor product of the input GLWE
/// secret key with itself in the standard domain.
impl
    GlweSecretKeyTensorProductSameKeyEngine<
        GlweSecretKey32,
        FftwFourierGlweTensorProductSecretKey32,
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
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// // We create the secret key
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// // Then compute the tensor product between the key and itself
    /// let tensor_product_key = fftw_engine.create_tensor_product_glwe_secret_key_same_key(&key)?;
    ///
    /// assert_eq!(
    ///     tensor_product_key.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_key.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// fftw_engine.destroy(tensor_product_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_tensor_product_glwe_secret_key_same_key(
        &mut self,
        input: &GlweSecretKey32,
    ) -> Result<
        FftwFourierGlweTensorProductSecretKey32,
        GlweSecretKeyTensorProductSameKeyError<Self::EngineError>,
    > {
        Ok(unsafe { self.create_tensor_product_glwe_secret_key_same_key_unchecked(input) })
    }

    unsafe fn create_tensor_product_glwe_secret_key_same_key_unchecked(
        &mut self,
        input: &GlweSecretKey32,
    ) -> FftwFourierGlweTensorProductSecretKey32 {
        let buffers = self.get_fourier_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let mut fourier_input = ImplFourierGlweSecretKey::allocate(
            Complex64::new(0., 0.),
            input.polynomial_size(),
            GlweDimension(input.glwe_dimension().0),
        );
        fourier_input.fill_with_forward_fourier(&input.0, buffers);

        FftwFourierGlweTensorProductSecretKey32(fourier_input.create_tensor_product_key())
    }
}

/// # Description:
/// Implementation of [`GlweSecretKeyTensorProductSameKeyEngine`] for
/// [`FftwEngine`] that operates on 64 bits integers. It outputs a tensor product of the input GLWE
/// secret key with itself in the standard domain.
impl
    GlweSecretKeyTensorProductSameKeyEngine<
        GlweSecretKey64,
        FftwFourierGlweTensorProductSecretKey64,
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
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// // We create the secret key
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// // Then compute the tensor product between the key and itself
    /// let tensor_product_key = fftw_engine.create_tensor_product_glwe_secret_key_same_key(&key)?;
    ///
    /// assert_eq!(
    ///     tensor_product_key.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_key.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// fftw_engine.destroy(tensor_product_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_tensor_product_glwe_secret_key_same_key(
        &mut self,
        input: &GlweSecretKey64,
    ) -> Result<
        FftwFourierGlweTensorProductSecretKey64,
        GlweSecretKeyTensorProductSameKeyError<Self::EngineError>,
    > {
        Ok(unsafe { self.create_tensor_product_glwe_secret_key_same_key_unchecked(input) })
    }

    unsafe fn create_tensor_product_glwe_secret_key_same_key_unchecked(
        &mut self,
        input: &GlweSecretKey64,
    ) -> FftwFourierGlweTensorProductSecretKey64 {
        let buffers = self.get_fourier_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let mut fourier_input = ImplFourierGlweSecretKey::allocate(
            Complex64::new(0., 0.),
            input.polynomial_size(),
            GlweDimension(input.glwe_dimension().0),
        );
        fourier_input.fill_with_forward_fourier(&input.0, buffers);

        FftwFourierGlweTensorProductSecretKey64(fourier_input.create_tensor_product_key())
    }
}
