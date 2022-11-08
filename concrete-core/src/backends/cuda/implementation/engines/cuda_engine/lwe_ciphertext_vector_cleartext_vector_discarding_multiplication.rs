use crate::backends::cuda::private::crypto::lwe::list::execute_lwe_ciphertext_vector_cleartext_vector_multiplication_on_gpu;
use crate::prelude::{
    CudaCleartextVector32, CudaCleartextVector64, CudaEngine, CudaLweCiphertextVector32,
    CudaLweCiphertextVector64,
};
use crate::specification::engines::{
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine,
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine`] for
/// [`CudaEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
        CudaLweCiphertextVector32,
        CudaCleartextVector32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    fn discard_mul_lwe_ciphertext_vector_cleartext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input_1: &CudaLweCiphertextVector32,
        input_2: &CudaCleartextVector32,
    ) -> Result<
        (),
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<Self::EngineError>,
    > {
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input_1: &CudaLweCiphertextVector32,
        input_2: &CudaCleartextVector32,
    ) {
        execute_lwe_ciphertext_vector_cleartext_vector_multiplication_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input_1.0,
            &input_2.0,
            self.get_number_of_gpus(),
        );
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine`] for
/// [`CudaEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorCleartextVectorDiscardingMultiplicationEngine<
        CudaLweCiphertextVector64,
        CudaCleartextVector64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    fn discard_mul_lwe_ciphertext_vector_cleartext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input_1: &CudaLweCiphertextVector64,
        input_2: &CudaCleartextVector64,
    ) -> Result<
        (),
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError<Self::EngineError>,
    > {
        LweCiphertextVectorCleartextVectorDiscardingMultiplicationError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe {
            self.discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
                output, input_1, input_2,
            )
        };
        Ok(())
    }

    unsafe fn discard_mul_lwe_ciphertext_vector_cleartext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input_1: &CudaLweCiphertextVector64,
        input_2: &CudaCleartextVector64,
    ) {
        execute_lwe_ciphertext_vector_cleartext_vector_multiplication_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input_1.0,
            &input_2.0,
            self.get_number_of_gpus(),
        );
    }
}
