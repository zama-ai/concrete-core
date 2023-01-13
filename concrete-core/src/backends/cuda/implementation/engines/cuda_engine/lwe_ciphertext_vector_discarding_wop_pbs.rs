use crate::backends::cuda::implementation::engines::{check_glwe_dim, CudaEngine};
use crate::backends::cuda::private::crypto::wopbs::execute_wop_pbs_on_gpu;
use crate::prelude::{CudaError, CudaFourierLweBootstrapKey64, CudaLweCiphertextVector64, CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, CudaLweKeyswitchKey64, CudaPlaintextVector64, DecompositionBaseLog, DecompositionLevelCount, LweBootstrapKeyEntity, LweCiphertextVectorDiscardingWopPbsEngine, LweCiphertextVectorDiscardingWopPbsError, MessageBitsCount};

impl From<CudaError>
    for LweCiphertextVectorDiscardingWopPbsError<CudaError>
{
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextVectorDiscardingWopPbsEngine<
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
        CudaFourierLweBootstrapKey64,
        CudaLweKeyswitchKey64,
        CudaPlaintextVector64,
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for CudaEngine
{
    fn discard_wop_pbs_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
        ksk: &CudaLweKeyswitchKey64,
        luts: &CudaPlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingWopPbsError<Self::EngineError>,
    > {
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        let glwe_dim = bsk.glwe_dimension();
        check_glwe_dim!(glwe_dim);
        LweCiphertextVectorDiscardingWopPbsError::
        perform_generic_checks(
            input,
            output,
            bsk,
            ksk,
            luts,
            cbs_level_count,
            cbs_base_log,
            cbs_pfpksk,
            64,
        )?;
        unsafe {
            self.discard_wop_pbs_lwe_ciphertext_vector_unchecked(
                output,
                input,
                bsk,
                ksk,
                luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
                number_of_bits_of_message_including_padding,
            );
        }
        Ok(())
    }

    unsafe fn discard_wop_pbs_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
        ksk: &CudaLweKeyswitchKey64,
        luts: &CudaPlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) {
        execute_wop_pbs_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &luts.0,
            &bsk.0,
            &ksk.0,
            &cbs_pfpksk.0,
            cbs_level_count,
            cbs_base_log,
            number_of_bits_of_message_including_padding,
            self.get_cuda_shared_memory(),
        );
    }
}
