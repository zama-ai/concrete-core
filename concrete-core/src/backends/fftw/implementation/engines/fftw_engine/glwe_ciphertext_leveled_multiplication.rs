use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{
    FftwFourierGlweCiphertext32, FftwFourierGlweCiphertext64,
};
use crate::backends::fftw::private::crypto::relinearize::StandardGlweRelinearizationKey;
use crate::backends::fftw::private::math::fft::ALLOWED_POLY_SIZE;
use crate::prelude::{FftwError, FftwFourierGlweMultiplicationCiphertext32, FftwFourierGlweMultiplicationCiphertext64, FftwStandardGlweRelinearizationKey32, FftwStandardGlweRelinearizationKey64, GlweCiphertext32, GlweCiphertext64, GlweCiphertextConversionEngine, GlweCiphertextEntity, GlweCiphertextLeveledMultiplicationEngine, GlweCiphertextLeveledMultiplicationError, ScalingFactor};

impl From<FftwError> for GlweCiphertextLeveledMultiplicationError<FftwError> {
    fn from(err: FftwError) -> Self {
        Self::Engine(err)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextLeveledMultiplicationEngine`] for [`FftwEngine`] that operates on 32-bit
/// integer GLWE Ciphertexts.
impl
    GlweCiphertextLeveledMultiplicationEngine<
        GlweCiphertext32,
        FftwStandardGlweRelinearizationKey32,
        FftwFourierGlweCiphertext32,
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
    /// let decomposition_base_log = DecompositionBaseLog(7);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = vec![3_u32 << 20; 256];
    /// let input_2 = vec![4_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// // We set up a scaling factor which is the bit shift used to encode the messages
    /// let scaling_factor = ScalingFactor(1 << 20);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_1, 
    /// noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_2, 
    /// noise)?;
    /// // Create a relinearization key
    /// let rlk = fftw_engine.create_glwe_relinearization_key(&glwe_key, decomposition_base_log, 
    /// decomposition_level_count, noise)?;
    /// // Compute the leveled multiplication between the ciphertexts
    /// // The result is in the Fourier domain
    /// let multiplied_ciphertext = fftw_engine.compute_leveled_multiplication_glwe_ciphertexts
    /// (&ciphertext_1, &ciphertext_2, &rlk, scaling_factor)?;
    ///
    /// assert_eq!(multiplied_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(multiplied_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(glwe_key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(rlk)?;
    /// fftw_engine.destroy(multiplied_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn compute_leveled_multiplication_glwe_ciphertexts(
        &mut self,
        input1: &GlweCiphertext32,
        input2: &GlweCiphertext32,
        rlk: &FftwStandardGlweRelinearizationKey32,
        scale: ScalingFactor,
    ) -> Result<FftwFourierGlweCiphertext32, 
        GlweCiphertextLeveledMultiplicationError<Self::EngineError>>
    {
        GlweCiphertextLeveledMultiplicationError::perform_generic_checks(input1, input2)?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u32::MAX as u64 {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        } 
        Ok(
            unsafe {
                self.compute_leveled_multiplication_glwe_ciphertexts_unchecked(input1, input2, rlk, scale)
            },
        )
    }

    unsafe fn compute_leveled_multiplication_glwe_ciphertexts_unchecked(
        &mut self,
        input1: &GlweCiphertext32,
        input2: &GlweCiphertext32,
        rlk: &StandardGlweRelinearizationKey32,
        scale: ScalingFactor,
    ) -> FftwFourierGlweMultiplicationCiphertext32 {
        let fourier1: FftwFourierGlweCiphertext32 = self.convert_glwe_ciphertext(input1).unwrap();
        let fourier2: FftwFourierGlweCiphertext32 = self.convert_glwe_ciphertext(input2).unwrap();
        let buffers = self.get_fourier_u32_buffer(
            input1.polynomial_size(),
            input1.glwe_dimension().to_glwe_size(),
        );
        FftwFourierGlweCiphertext32(
            fourier1
                .0
                .compute_leveled_multiplication(&fourier2.0, scale, rlk, buffers),
        )
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextLeveledMultiplicationEngine`] for [`FftwEngine`] that operates on 64-bit
/// integer GLWE Ciphertexts.
impl
GlweCiphertextLeveledMultiplicationEngine<
    GlweCiphertext64,
    FftwStandardGlweRelinearizationKey64,
    FftwFourierGlweCiphertext64,
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
    /// let decomposition_base_log = DecompositionBaseLog(7);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = vec![3_u64 << 50; 256];
    /// let input_2 = vec![4_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// // We set up a scaling factor which is the bit shift used to encode the messages
    /// let scaling_factor = ScalingFactor(1 << 50);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_1, 
    /// noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_2, 
    /// noise)?;
    /// // Create a relinearization key
    /// let rlk = fftw_engine.create_glwe_relinearization_key(&glwe_key, decomposition_base_log, 
    /// decomposition_level_count, noise)?;
    /// // Compute the leveled multiplication between the ciphertexts
    /// // The result is in the Fourier domain
    /// let multiplied_ciphertext = fftw_engine.compute_leveled_multiplication_glwe_ciphertexts
    /// (&ciphertext_1, &ciphertext_2, &rlk, scaling_factor)?;
    ///
    /// assert_eq!(multiplied_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(multiplied_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(glwe_key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// fftw_engine.destroy(rlk)?;
    /// fftw_engine.destroy(multiplied_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn compute_leveled_multiplication_glwe_ciphertexts(
        &mut self,
        input1: &GlweCiphertext64,
        input2: &GlweCiphertext64,
        rlk: &FftwStandardGlweRelinearizationKey64,
        scale: ScalingFactor,
    ) -> Result<FftwFourierGlweCiphertext64,
        GlweCiphertextLeveledMultiplicationError<Self::EngineError>>
    {
        GlweCiphertextLeveledMultiplicationError::perform_generic_checks(input1, input2)?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u64::MAX as u64 {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.compute_leveled_multiplication_glwe_ciphertexts_unchecked(input1, input2, rlk, scale)
            },
        )
    }

    unsafe fn compute_leveled_multiplication_glwe_ciphertexts_unchecked(
        &mut self,
        input1: &GlweCiphertext64,
        input2: &GlweCiphertext64,
        rlk: &StandardGlweRelinearizationKey64,
        scale: ScalingFactor,
    ) -> FftwFourierGlweMultiplicationCiphertext64 {
        let fourier1: FftwFourierGlweCiphertext64 = self.convert_glwe_ciphertext(input1).unwrap();
        let fourier2: FftwFourierGlweCiphertext64 = self.convert_glwe_ciphertext(input2).unwrap();
        let buffers = self.get_fourier_u64_buffer(
            input1.polynomial_size(),
            input1.glwe_dimension().to_glwe_size(),
        );
        FftwFourierGlweCiphertext64(
            fourier1
                .0
                .compute_leveled_multiplication(&fourier2.0, scale, rlk, buffers),
        )
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextLeveledMultiplicationEngine`] for [`FftwEngine`] that operates on 32-bit
/// integer GLWE Ciphertexts in the Fourier domain.
impl
GlweCiphertextLeveledMultiplicationEngine<
    FftwFourierGlweCiphertext32,
    FftwStandardGlweRelinearizationKey32,
    FftwFourierGlweCiphertext32,
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
    /// let decomposition_base_log = DecompositionBaseLog(7);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = vec![3_u32 << 20; 256];
    /// let input_2 = vec![4_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// // We set up a scaling factor which is the bit shift used to encode the messages
    /// let scaling_factor = ScalingFactor(1 << 20);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_1, 
    /// noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_2, 
    /// noise)?;
    /// let fourier_ciphertext_1 = fftw_engine.convert_glwe_ciphertext(&ciphertext_1)?;
    /// let fourier_ciphertext_2 = fftw_engine.convert_glwe_ciphertext(&ciphertext_2)?;
    /// // Create a relinearization key
    /// let rlk = fftw_engine.create_glwe_relinearization_key(&glwe_key, decomposition_base_log, 
    /// decomposition_level_count, noise)?;
    /// // Compute the leveled multiplication between the ciphertexts
    /// // The result is in the Fourier domain
    /// let multiplied_ciphertext = fftw_engine.compute_leveled_multiplication_glwe_ciphertexts
    /// (&fourier_ciphertext_1, &fourier_ciphertext_2, &rlk, scaling_factor)?;
    ///
    /// assert_eq!(multiplied_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(multiplied_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(glwe_key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// default_engine.destroy(fourier_ciphertext_1)?;
    /// default_engine.destroy(fourier_ciphertext_2)?;
    /// fftw_engine.destroy(rlk)?;
    /// fftw_engine.destroy(multiplied_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn compute_leveled_multiplication_glwe_ciphertexts(
        &mut self,
        input1: &FftwFourierGlweCiphertext32,
        input2: &FftwFourierGlweCiphertext32,
        rlk: &FftwStandardGlweRelinearizationKey32,
        scale: ScalingFactor,
    ) -> Result<FftwFourierGlweCiphertext32,
        GlweCiphertextLeveledMultiplicationError<Self::EngineError>>
    {
        GlweCiphertextLeveledMultiplicationError::perform_generic_checks(input1, input2)?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u32::MAX as u64 {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.compute_leveled_multiplication_glwe_ciphertexts_unchecked(input1, input2, rlk, scale)
            },
        )
    }

    unsafe fn compute_leveled_multiplication_glwe_ciphertexts_unchecked(
        &mut self,
        input1: &FftwFourierGlweCiphertext32,
        input2: &FftwFourierGlweCiphertext32,
        rlk: &StandardGlweRelinearizationKey32,
        scale: ScalingFactor,
    ) -> FftwFourierGlweMultiplicationCiphertext32 {
        let buffers = self.get_fourier_u32_buffer(
            input1.polynomial_size(),
            input1.glwe_dimension().to_glwe_size(),
        );
        FftwFourierGlweCiphertext32(
            input1
                .0
                .compute_leveled_multiplication(&input2.0, scale, rlk, buffers),
        )
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextLeveledMultiplicationEngine`] for [`FftwEngine`] that operates on 64-bit
/// integer GLWE Ciphertexts in the Fourier domain.
impl
GlweCiphertextLeveledMultiplicationEngine<
    FftwFourierGlweCiphertext64,
    FftwStandardGlweRelinearizationKey64,
    FftwFourierGlweCiphertext64,
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
    /// let decomposition_base_log = DecompositionBaseLog(7);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = vec![3_u64 << 50; 256];
    /// let input_2 = vec![4_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-50.));
    /// // We set up a scaling factor which is the bit shift used to encode the messages
    /// let scaling_factor = ScalingFactor(1 << 50);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let glwe_key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector_1 = default_engine.create_plaintext_vector(&input_1)?;
    /// let plaintext_vector_2 = default_engine.create_plaintext_vector(&input_2)?;
    ///
    /// // We encrypt two GLWE ciphertexts in the standard domain
    /// let ciphertext_1 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_1, 
    /// noise)?;
    /// let ciphertext_2 = default_engine.encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector_2, 
    /// noise)?;
    /// let fourier_ciphertext_1 = fftw_engine.convert_glwe_ciphertext(&ciphertext_1)?;
    /// let fourier_ciphertext_2 = fftw_engine.convert_glwe_ciphertext(&ciphertext_2)?;
    /// // Create a relinearization key
    /// let rlk = fftw_engine.create_glwe_relinearization_key(&glwe_key, decomposition_base_log, 
    /// decomposition_level_count, noise)?;
    /// // Compute the leveled multiplication between the ciphertexts
    /// // The result is in the Fourier domain
    /// let multiplied_ciphertext = fftw_engine.compute_leveled_multiplication_glwe_ciphertexts
    /// (&fourier_ciphertext_1, &fourier_ciphertext_2, &rlk, scaling_factor)?;
    ///
    /// assert_eq!(multiplied_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(multiplied_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// default_engine.destroy(glwe_key)?;
    /// default_engine.destroy(plaintext_vector_1)?;
    /// default_engine.destroy(plaintext_vector_2)?;
    /// default_engine.destroy(ciphertext_1)?;
    /// default_engine.destroy(ciphertext_2)?;
    /// default_engine.destroy(fourier_ciphertext_1)?;
    /// default_engine.destroy(fourier_ciphertext_2)?;
    /// fftw_engine.destroy(rlk)?;
    /// fftw_engine.destroy(multiplied_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn compute_leveled_multiplication_glwe_ciphertexts(
        &mut self,
        input1: &FftwFourierGlweCiphertext64,
        input2: &FftwFourierGlweCiphertext64,
        rlk: &FftwStandardGlweRelinearizationKey64,
        scale: ScalingFactor,
    ) -> Result<FftwFourierGlweCiphertext64,
        GlweCiphertextLeveledMultiplicationError<Self::EngineError>>
    {
        GlweCiphertextLeveledMultiplicationError::perform_generic_checks(input1, input2)?;
        if !ALLOWED_POLY_SIZE.contains(&glwe_input.polynomial_size().0) {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::UnsupportedPolynomialSize,
            ));
        }
        if scale.0 >= u64::MAX as u64 {
            return Err(GlweCiphertextLeveledMultiplicationError::from(
                FftwError::ScalingFactorTooLarge,
            ));
        }
        Ok(
            unsafe {
                self.compute_leveled_multiplication_glwe_ciphertexts_unchecked(input1, input2, rlk, scale)
            },
        )
    }

    unsafe fn compute_leveled_multiplication_glwe_ciphertexts_unchecked(
        &mut self,
        input1: &FftwFourierGlweCiphertext64,
        input2: &FftwFourierGlweCiphertext64,
        rlk: &StandardGlweRelinearizationKey64,
        scale: ScalingFactor,
    ) -> FftwFourierGlweMultiplicationCiphertext64 {
        let buffers = self.get_fourier_u64_buffer(
            input1.polynomial_size(),
            input1.glwe_dimension().to_glwe_size(),
        );
        FftwFourierGlweCiphertext64(
            input1
                .0
                .compute_leveled_multiplication(&input2.0, scale, rlk, buffers),
        )
    }
}

