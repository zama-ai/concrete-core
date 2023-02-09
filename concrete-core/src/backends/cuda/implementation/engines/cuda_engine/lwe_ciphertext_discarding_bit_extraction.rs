use crate::backends::cuda::private::crypto::bootstrap::execute_lwe_ciphertext_vector_extract_bits_on_gpu;
use crate::prelude::{
    CiphertextModulusLog, CudaEngine, CudaError, CudaFourierLweBootstrapKey32,
    CudaFourierLweBootstrapKey64, CudaLweCiphertext32, CudaLweCiphertext64,
    CudaLweCiphertextVector32, CudaLweCiphertextVector64, CudaLweKeyswitchKey32,
    CudaLweKeyswitchKey64, DeltaLog, ExtractedBitsCount, LweBootstrapKeyEntity, LweCiphertextCount,
    LweCiphertextEntity, LweCiphertextVectorEntity, LweKeyswitchKeyEntity,
};
use crate::specification::engines::{
    LweCiphertextDiscardingBitExtractEngine, LweCiphertextDiscardingBitExtractError,
};

impl From<CudaError> for LweCiphertextDiscardingBitExtractError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextDiscardingBitExtractEngine<
        CudaFourierLweBootstrapKey32,
        CudaLweKeyswitchKey32,
        CudaLweCiphertext32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
        ksk: &CudaLweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(32),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
        ksk: &CudaLweKeyswitchKey32,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let output_lwe_dimension = output.lwe_dimension();
        execute_lwe_ciphertext_vector_extract_bits_on_gpu::<u32>(
            self.get_cuda_streams(),
            output.0.d_vecs.get_mut(0).unwrap(),
            &input.0.d_vec,
            ksk.0.d_vecs.get(0).unwrap(),
            bsk.0.d_vecs.get(0).unwrap(),
            extracted_bits_count,
            delta_log,
            input.lwe_dimension(),
            output_lwe_dimension,
            bsk.glwe_dimension(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            ksk.decomposition_base_log(),
            ksk.decomposition_level_count(),
            LweCiphertextCount(1),
            self.get_cuda_shared_memory(),
        );
    }
}

impl
    LweCiphertextDiscardingBitExtractEngine<
        CudaFourierLweBootstrapKey64,
        CudaLweKeyswitchKey64,
        CudaLweCiphertext64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    fn discard_extract_bits_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
        ksk: &CudaLweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) -> Result<(), LweCiphertextDiscardingBitExtractError<Self::EngineError>> {
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        LweCiphertextDiscardingBitExtractError::perform_generic_checks(
            output,
            input,
            bsk,
            ksk,
            extracted_bits_count,
            CiphertextModulusLog(64),
            delta_log,
        )?;
        unsafe {
            self.discard_extract_bits_lwe_ciphertext_unchecked(
                output,
                input,
                bsk,
                ksk,
                extracted_bits_count,
                delta_log,
            )
        };
        Ok(())
    }

    unsafe fn discard_extract_bits_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
        ksk: &CudaLweKeyswitchKey64,
        extracted_bits_count: ExtractedBitsCount,
        delta_log: DeltaLog,
    ) {
        let output_lwe_dimension = output.lwe_dimension();
        execute_lwe_ciphertext_vector_extract_bits_on_gpu::<u64>(
            self.get_cuda_streams(),
            output.0.d_vecs.get_mut(0).unwrap(),
            &input.0.d_vec,
            ksk.0.d_vecs.get(0).unwrap(),
            bsk.0.d_vecs.get(0).unwrap(),
            extracted_bits_count,
            delta_log,
            input.lwe_dimension(),
            output_lwe_dimension,
            bsk.glwe_dimension(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            ksk.decomposition_base_log(),
            ksk.decomposition_level_count(),
            LweCiphertextCount(1),
            self.get_cuda_shared_memory(),
        );
    }
}
