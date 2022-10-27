use crate::backends::cuda::private::crypto::lwe::list::execute_lwe_ciphertext_vector_addition_on_gpu;
use crate::prelude::{
    CudaEngine, CudaLweCiphertextVector32, CudaLweCiphertextVector64,
    LweCiphertextVectorDiscardingAdditionEngine, LweCiphertextVectorDiscardingAdditionError,
};

impl
    LweCiphertextVectorDiscardingAdditionEngine<
        CudaLweCiphertextVector32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    fn discard_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input_1: &CudaLweCiphertextVector32,
        input_2: &CudaLweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorDiscardingAdditionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_add_lwe_ciphertext_vector_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input_1: &CudaLweCiphertextVector32,
        input_2: &CudaLweCiphertextVector32,
    ) {
        execute_lwe_ciphertext_vector_addition_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input_1.0,
            &input_2.0,
            self.get_number_of_gpus(),
        );
    }
}

impl
    LweCiphertextVectorDiscardingAdditionEngine<
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    fn discard_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input_1: &CudaLweCiphertextVector64,
        input_2: &CudaLweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingAdditionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingAdditionError::perform_generic_checks(
            output, input_1, input_2,
        )?;
        unsafe { self.discard_add_lwe_ciphertext_vector_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn discard_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input_1: &CudaLweCiphertextVector64,
        input_2: &CudaLweCiphertextVector64,
    ) {
        execute_lwe_ciphertext_vector_addition_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input_1.0,
            &input_2.0,
            self.get_number_of_gpus(),
        );
    }
}
