use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::private::crypto::wopbs::execute_circuit_bootstrap_vertical_packing_on_gpu;
use crate::prelude::{
    CudaError, CudaFourierLweBootstrapKey64, CudaLweCiphertextVector64,
    CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, CudaPlaintextVector64,
    DecompositionBaseLog, DecompositionLevelCount, LweBootstrapKeyEntity,
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine,
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError,
};

impl From<CudaError>
    for LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<CudaError>
{
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine<
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
        CudaFourierLweBootstrapKey64,
        CudaPlaintextVector64,
        CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for CudaEngine
{
    fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
        luts: &CudaPlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<Self::EngineError>,
    > {
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError::
        perform_generic_checks(
            input,
            output,
            bsk,
            luts,
            cbs_level_count,
            cbs_base_log,
            cbs_pfpksk,
            64,
        )?;
        unsafe {
            self.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
                output,
                input,
                bsk,
                luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
            );
        }
        Ok(())
    }

    unsafe fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
        luts: &CudaPlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) {
        execute_circuit_bootstrap_vertical_packing_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &luts.0,
            &bsk.0,
            &cbs_pfpksk.0,
            cbs_level_count,
            cbs_base_log,
            self.get_cuda_shared_memory(),
        );
    }
}
