use crate::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::backends::cuda::implementation::entities::CudaLweCiphertextVector64;
use crate::backends::cuda::private::device::GpuIndex;
use crate::prelude::LweCiphertextVectorMutView64;
use crate::specification::engines::{
    LweCiphertextVectorDiscardingConversionEngine, LweCiphertextVectorDiscardingConversionError,
};
use crate::specification::entities::LweCiphertextVectorEntity;

impl From<CudaError> for LweCiphertextVectorDiscardingConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from GPU to a view on CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVectorView64 on the CPU.
impl
    LweCiphertextVectorDiscardingConversionEngine<
        CudaLweCiphertextVector64,
        LweCiphertextVectorMutView64<'_>,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 = default_engine.create_plaintext_vector(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let lwe_ciphertext_count = d_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = LweSize(d_ciphertext_vector.lwe_dimension().0 + 1);
    /// ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext_vector = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    /// let mut h_view_output_ciphertext_vector: LweCiphertextVectorMutView64 = default_engine
    ///     .create_lwe_ciphertext_vector(h_raw_output_ciphertext_vector.as_mut_slice(), lwe_size)?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext_vector(
    ///     h_view_output_ciphertext_vector.borrow_mut(),
    ///     &d_ciphertext_vector,
    /// )?;
    ///
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_dimension(),
    ///     lwe_dimension
    /// );
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_raw_output_ciphertext_vector: &[u64] =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_view_output_ciphertext_vector)?;
    /// assert_eq!(
    ///     h_raw_input_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// default_engine.destroy(h_key)?;
    /// default_engine.destroy(h_plaintext_vector)?;
    /// cuda_engine.destroy(d_ciphertext_vector);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &CudaLweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &CudaLweCiphertextVector64,
    ) {
        // Split the input vector over GPUs
        let samples_per_gpu = input.lwe_ciphertext_count().0 / self.get_number_of_gpus() as usize;
        let data_per_gpu = samples_per_gpu * input.lwe_dimension().to_lwe_size().0;

        let output_container = output.0.tensor.as_mut_container();
        for (gpu_index, chunks) in output_container.chunks_exact_mut(data_per_gpu).enumerate() {
            let stream = &self.streams[gpu_index];
            stream.copy_to_cpu::<u64>(chunks, input.0.get_ptr(GpuIndex(gpu_index as u32)).0);
        }
        let last_chunk = output_container
            .chunks_exact_mut(data_per_gpu)
            .into_remainder();
        let stream = &self.streams[self.get_number_of_gpus() - 1];
        stream.copy_to_cpu::<u64>(
            last_chunk,
            input
                .0
                .get_ptr(GpuIndex(self.get_number_of_gpus() as u32 - 1))
                .0,
        );
    }
}
