use crate::backends::cuda::engines::CudaError;
use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, CudaGlweCiphertext32,
    CudaGlweCiphertext64, CudaLweCiphertext32, CudaLweCiphertext64,
};
use crate::backends::cuda::private::device::GpuIndex;
use crate::specification::engines::{
    LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingBootstrapError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

impl From<CudaError> for LweCiphertextDiscardingBootstrapError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard bootstrap on an input ciphertext with 32 bits of precision.
/// The input bootstrap key is in the Fourier domain.
impl
    LweCiphertextDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey32,
        CudaGlweCiphertext32,
        CudaLweCiphertext32,
        CudaLweCiphertext32,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(130),
    ///     LweDimension(512),
    ///     GlweDimension(1),
    ///     PolynomialSize(512),
    /// );
    /// let log_degree = f64::log2(poly_size.0 as f64) as i32;
    /// let val: u32 = ((poly_size.0 as f64 - (10. * f64::sqrt((lwe_dim.0 as f64) / 16.0)))
    ///     * 2_f64.powi(32 - log_degree - 1)) as u32;
    /// let input = val;
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u32; poly_size.0];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi(32 - log_degree - 1)) as u32;
    ///     lut[i] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext: Plaintext32 = default_engine.create_plaintext(&input)?;
    /// let mut h_input_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_input_key, &h_input_plaintext, noise)?;
    /// // create a GLWE ciphertext containing an encryption of the LUT
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector(&lut)?;
    /// let h_lut_key: GlweSecretKey32 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut =
    ///     default_engine.encrypt_glwe_ciphertext(&h_lut_key, &h_lut_plaintext_vector, noise)?;
    /// // create a BSK
    /// let h_bootstrap_key: LweBootstrapKey32 =
    ///     default_engine.create_lwe_bootstrap_key(&h_input_key, &h_lut_key, dec_bl, dec_lc, noise)?;
    /// // initialize an output LWE ciphertext vector
    /// let h_dummy_key: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dim_output)?;
    ///
    /// // 2. cuda engine
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// // convert input to GPU 0
    /// let d_input_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_input_ciphertext)?;
    /// // convert accumulator to GPU
    /// let d_input_lut: CudaGlweCiphertext32 = cuda_engine.convert_glwe_ciphertext(&h_lut)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey32 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext: LweCiphertext32 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    /// let mut d_output_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_output_ciphertext)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext(
    ///     &mut d_output_ciphertext,
    ///     &d_input_ciphertext,
    ///     &d_input_lut,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// default_engine.destroy(h_input_key)?;
    /// default_engine.destroy(h_input_plaintext)?;
    /// default_engine.destroy(h_input_ciphertext)?;
    /// default_engine.destroy(h_lut_plaintext_vector)?;
    /// default_engine.destroy(h_lut_key)?;
    /// default_engine.destroy(h_lut)?;
    /// default_engine.destroy(h_bootstrap_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_zero_output_ciphertext)?;
    /// cuda_engine.destroy(d_input_ciphertext)?;
    /// cuda_engine.destroy(d_input_lut)?;
    /// cuda_engine.destroy(d_fourier_bsk)?;
    /// cuda_engine.destroy(d_output_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        acc: &CudaGlweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<CudaError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::OutputLweDimensionMismatch);
        }
        let poly_size = bsk.0.polynomial_size().0;
        check_poly_size!(poly_size);
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        acc: &CudaGlweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) {
        let stream = &self.streams[0];
        let test_vector_indexes = vec![0; 1];
        let d_test_vector_indexes = stream.malloc::<u32>(1);
        stream.copy_to_gpu(d_test_vector_indexes, &test_vector_indexes);

        stream.discard_bootstrap_low_latency_lwe_ciphertext_vector_32(
            output.0.get_ptr().0,
            acc.0.get_ptr().0,
            d_test_vector_indexes,
            input.0.get_ptr().0,
            bsk.0.get_ptr(GpuIndex(0)).0,
            input.lwe_dimension().0 as u32,
            bsk.polynomial_size().0 as u32,
            bsk.decomposition_base_log().0 as u32,
            bsk.decomposition_level_count().0 as u32,
            1,
            0,
            self.get_cuda_shared_memory() as u32,
        );
        stream.drop(d_test_vector_indexes).unwrap();
    }
}

/// # Description
/// A discard bootstrap on an input ciphertext with 64 bits of precision.
/// The input bootstrap key is in the Fourier domain.
impl
    LweCiphertextDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey64,
        CudaGlweCiphertext64,
        CudaLweCiphertext64,
        CudaLweCiphertext64,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(130),
    ///     LweDimension(512),
    ///     GlweDimension(1),
    ///     PolynomialSize(512),
    /// );
    /// let log_degree = f64::log2(poly_size.0 as f64) as i64;
    /// let val: u64 = ((poly_size.0 as f64 - (10. * f64::sqrt((lwe_dim.0 as f64) / 16.0)))
    ///     * 2_f64.powi((64 - log_degree - 1) as i32)) as u64;
    /// let input = val;
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u64; poly_size.0];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi((64 - log_degree - 1) as i32)) as u64;
    ///     lut[i] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext: Plaintext64 = default_engine.create_plaintext(&input)?;
    /// let mut h_input_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_input_key, &h_input_plaintext, noise)?;
    /// // create a GLWE ciphertext containing an encryption of the LUT
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector(&lut)?;
    /// let h_lut_key: GlweSecretKey64 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut =
    ///     default_engine.encrypt_glwe_ciphertext(&h_lut_key, &h_lut_plaintext_vector, noise)?;
    /// // create a BSK
    /// let h_bootstrap_key: LweBootstrapKey64 =
    ///     default_engine.create_lwe_bootstrap_key(&h_input_key, &h_lut_key, dec_bl, dec_lc, noise)?;
    /// // initialize an output LWE ciphertext vector
    /// let h_dummy_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dim_output)?;
    ///
    /// // 2. cuda engine
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// // convert input to GPU 0
    /// let d_input_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_input_ciphertext)?;
    /// // convert accumulator to GPU
    /// let d_input_lut: CudaGlweCiphertext64 = cuda_engine.convert_glwe_ciphertext(&h_lut)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey64 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext: LweCiphertext64 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    /// let mut d_output_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_output_ciphertext)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext(
    ///     &mut d_output_ciphertext,
    ///     &d_input_ciphertext,
    ///     &d_input_lut,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// default_engine.destroy(h_input_key)?;
    /// default_engine.destroy(h_input_plaintext)?;
    /// default_engine.destroy(h_input_ciphertext)?;
    /// default_engine.destroy(h_lut_plaintext_vector)?;
    /// default_engine.destroy(h_lut_key)?;
    /// default_engine.destroy(h_lut)?;
    /// default_engine.destroy(h_bootstrap_key)?;
    /// default_engine.destroy(h_dummy_key)?;
    /// default_engine.destroy(h_zero_output_ciphertext)?;
    /// cuda_engine.destroy(d_input_ciphertext)?;
    /// cuda_engine.destroy(d_input_lut)?;
    /// cuda_engine.destroy(d_fourier_bsk)?;
    /// cuda_engine.destroy(d_output_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        acc: &CudaGlweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<CudaError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::OutputLweDimensionMismatch);
        }
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        let poly_size = bsk.0.polynomial_size().0;
        check_poly_size!(poly_size);
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        acc: &CudaGlweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) {
        let stream = &self.streams[0];
        let test_vector_indexes = vec![0; 1];
        let d_test_vector_indexes = stream.malloc::<u64>(1);
        stream.copy_to_gpu(d_test_vector_indexes, &test_vector_indexes);

        stream.discard_bootstrap_low_latency_lwe_ciphertext_vector_64(
            output.0.get_ptr().0,
            acc.0.get_ptr().0,
            d_test_vector_indexes,
            input.0.get_ptr().0,
            bsk.0.get_ptr(GpuIndex(0)).0,
            input.lwe_dimension().0 as u32,
            bsk.polynomial_size().0 as u32,
            bsk.decomposition_base_log().0 as u32,
            bsk.decomposition_level_count().0 as u32,
            1,
            0,
            self.get_cuda_shared_memory() as u32,
        );
        stream.drop(d_test_vector_indexes).unwrap();
    }
}
