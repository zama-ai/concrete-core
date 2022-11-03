use crate::backends::cuda::private::crypto::keyswitch::execute_lwe_ciphertext_vector_fp_keyswitch_on_gpu;
use crate::prelude::{
    CudaEngine, CudaGlweCiphertext32, CudaGlweCiphertext64, CudaLweCiphertextVector32,
    CudaLweCiphertextVector64, CudaLwePrivateFunctionalPackingKeyswitchKey32,
    CudaLwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::specification::engines::{
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine,
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError,
};

/// # Description:
/// Implementation of
/// [`LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine`] for
/// [`CudaEngine`] that operates on 32 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
        CudaLwePrivateFunctionalPackingKeyswitchKey32,
        CudaLweCiphertextVector32,
        CudaGlweCiphertext32,
    > for CudaEngine
{
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaGlweCiphertext32,
        input: &CudaLweCiphertextVector32,
        pfpksk: &CudaLwePrivateFunctionalPackingKeyswitchKey32,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, pfpksk,
        )?;
        unsafe {
            self.discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
                output, input, pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaGlweCiphertext32,
        input: &CudaLweCiphertextVector32,
        pfpksk: &CudaLwePrivateFunctionalPackingKeyswitchKey32,
    ) {
        execute_lwe_ciphertext_vector_fp_keyswitch_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &pfpksk.0,
            self.get_number_of_gpus(),
        );
    }
}
/// # Description:
/// Implementation of
/// [`LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine`] for
/// [`CudaEngine`] that operates on 64 bits integers.
impl
    LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchEngine<
        CudaLwePrivateFunctionalPackingKeyswitchKey64,
        CudaLweCiphertextVector64,
        CudaGlweCiphertext64,
    > for CudaEngine
{
    fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaGlweCiphertext64,
        input: &CudaLweCiphertextVector64,
        pfpksk: &CudaLwePrivateFunctionalPackingKeyswitchKey64,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError<
            Self::EngineError,
        >,
    > {
        LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchError
        ::perform_generic_checks(
            output, input, pfpksk,
        )?;
        unsafe {
            self.discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
                output, input, pfpksk,
            )
        };
        Ok(())
    }

    unsafe fn discard_private_functional_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaGlweCiphertext64,
        input: &CudaLweCiphertextVector64,
        pfpksk: &CudaLwePrivateFunctionalPackingKeyswitchKey64,
    ) {
        execute_lwe_ciphertext_vector_fp_keyswitch_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &pfpksk.0,
            self.get_number_of_gpus(),
        );
    }
}
