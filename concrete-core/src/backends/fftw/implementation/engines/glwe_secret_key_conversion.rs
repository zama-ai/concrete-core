use crate::backends::fftw::engines::{FftwEngine, FftwError};
use crate::backends::fftw::private::math::fft::ALLOWED_POLY_SIZE;
use crate::commons::crypto::secret::GlweSecretKey;
use crate::prelude::{
    FftwFourierGlweTensorProductSecretKey32, FftwFourierGlweTensorProductSecretKey64,
    GlweTensorProductSecretKey32, GlweTensorProductSecretKey64,
};
use crate::specification::engines::{GlweSecretKeyConversionEngine, GlweSecretKeyConversionError};
use crate::specification::entities::GlweSecretKeyEntity;

impl From<FftwError> for GlweSecretKeyConversionError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweSecretKeyConversionEngine`] for [`FftwEngine`] that operates on
/// 32 bits integers. It converts a tensor product GLWE secret key from the standard to the Fourier
/// domain.
impl
    GlweSecretKeyConversionEngine<
        FftwFourierGlweTensorProductSecretKey32,
        GlweTensorProductSecretKey32,
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
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// // Create a tensor product key in the Fourier domain
    /// let fourier_tensor_product_key =
    ///     fftw_engine.create_tensor_product_glwe_secret_key_same_key(&key)?;
    ///
    /// // Convert the tensor product key back to the standard domain
    /// let tensor_product_key: GlweTensorProductSecretKey32 =
    ///     fftw_engine.convert_glwe_secret_key(&fourier_tensor_product_key)?;
    /// #
    /// assert_eq!(
    ///     tensor_product_key.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_key.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// fftw_engine.destroy(fourier_tensor_product_key)?;
    /// default_engine.destroy(tensor_product_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_secret_key(
        &mut self,
        input: &FftwFourierGlweTensorProductSecretKey32,
    ) -> Result<GlweTensorProductSecretKey32, GlweSecretKeyConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweSecretKeyConversionError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_secret_key_unchecked(input) })
    }

    unsafe fn convert_glwe_secret_key_unchecked(
        &mut self,
        input: &FftwFourierGlweTensorProductSecretKey32,
    ) -> GlweTensorProductSecretKey32 {
        let mut output = GlweSecretKey::tensor_product_from_container(
            vec![0_u32; input.glwe_dimension().0 * input.polynomial_size().0],
            input.polynomial_size(),
        );
        let buffers = self.get_fourier_u32_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let mut input_ = input.0.clone();
        input_.fill_with_backward_fourier(&mut output, buffers);
        GlweTensorProductSecretKey32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSecretKeyConversionEngine`] for [`FftwEngine`] that operates on
/// 64 bits integers. It converts a tensor product GLWE secret key from the standard to the Fourier
/// domain.
impl
    GlweSecretKeyConversionEngine<
        FftwFourierGlweTensorProductSecretKey64,
        GlweTensorProductSecretKey64,
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
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// // Create a tensor product key in the Fourier domain
    /// let fourier_tensor_product_key =
    ///     fftw_engine.create_tensor_product_glwe_secret_key_same_key(&key)?;
    ///
    /// // Convert the tensor product key back to the standard domain
    /// let tensor_product_key: GlweTensorProductSecretKey64 =
    ///     fftw_engine.convert_glwe_secret_key(&fourier_tensor_product_key)?;
    /// #
    /// assert_eq!(
    ///     tensor_product_key.glwe_dimension(),
    ///     GlweDimension((glwe_dimension.0 * glwe_dimension.0 + 3 * glwe_dimension.0) / 2)
    /// );
    /// assert_eq!(tensor_product_key.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(key)?;
    /// fftw_engine.destroy(fourier_tensor_product_key)?;
    /// default_engine.destroy(tensor_product_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_secret_key(
        &mut self,
        input: &FftwFourierGlweTensorProductSecretKey64,
    ) -> Result<GlweTensorProductSecretKey64, GlweSecretKeyConversionError<Self::EngineError>> {
        if !ALLOWED_POLY_SIZE.contains(&input.polynomial_size().0) {
            return Err(GlweSecretKeyConversionError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }

        Ok(unsafe { self.convert_glwe_secret_key_unchecked(input) })
    }

    unsafe fn convert_glwe_secret_key_unchecked(
        &mut self,
        input: &FftwFourierGlweTensorProductSecretKey64,
    ) -> GlweTensorProductSecretKey64 {
        let mut output = GlweSecretKey::tensor_product_from_container(
            vec![0_u64; input.glwe_dimension().0 * input.polynomial_size().0],
            input.polynomial_size(),
        );
        let buffers = self.get_fourier_u64_buffer(
            input.polynomial_size(),
            input.glwe_dimension().to_glwe_size(),
        );
        let mut input_ = input.0.clone();
        input_.fill_with_backward_fourier(&mut output, buffers);
        GlweTensorProductSecretKey64(output)
    }
}
