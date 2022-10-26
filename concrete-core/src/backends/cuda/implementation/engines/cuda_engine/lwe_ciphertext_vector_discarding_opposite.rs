use crate::backends::cuda::private::crypto::lwe::list::execute_lwe_ciphertext_vector_opposite_on_gpu;
use crate::prelude::{
    CudaEngine, CudaLweCiphertextVector32, CudaLweCiphertextVector64,
    LweCiphertextVectorDiscardingOppositeEngine, LweCiphertextVectorDiscardingOppositeError,
};

impl
    LweCiphertextVectorDiscardingOppositeEngine<
        CudaLweCiphertextVector32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    fn discard_opp_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextVectorDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
    ) {
        execute_lwe_ciphertext_vector_opposite_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            self.get_number_of_gpus(),
        );
    }
}

impl
    LweCiphertextVectorDiscardingOppositeEngine<
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    fn discard_opp_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingOppositeError<Self::EngineError>> {
        LweCiphertextVectorDiscardingOppositeError::perform_generic_checks(output, input)?;
        unsafe { self.discard_opp_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_opp_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
    ) {
        execute_lwe_ciphertext_vector_opposite_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            self.get_number_of_gpus(),
        );
    }
}
