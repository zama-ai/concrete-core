use crate::prelude::{FftError, FftFourierLweBootstrapKey64, DecompositionBaseLog, DecompositionLevelCount, LweBootstrapKeyEntity, LweCiphertextVectorDiscardingWopPbsEngine, LweCiphertextVectorDiscardingWopPbsError, MessageBitsCount, FftEngine, LweCiphertextVector64, LweKeyswitchKey64, PlaintextVector64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCiphertextView64, LweCiphertextMutView64, FFT_ENGINE, LweCiphertextDiscardingWopPbsEngine};

use rayon::prelude::*;

impl From<FftError>
    for LweCiphertextVectorDiscardingWopPbsError<FftError>
{
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextVectorDiscardingWopPbsEngine<
        LweCiphertextVector64,
        LweCiphertextVector64,
        FftFourierLweBootstrapKey64,
        LweKeyswitchKey64,
        PlaintextVector64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for FftEngine
{
    fn discard_wop_pbs_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingWopPbsError<Self::EngineError>,
    > {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
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
        output: &mut LweCiphertextVector64,
        input: &LweCiphertextVector64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) {
        input
            .0
            .par_ciphertext_iter()
            .zip(output.0.par_ciphertext_iter_mut())
            .for_each(|(a, o)| {
                let a1 = LweCiphertextView64(a);
                let mut o1 = LweCiphertextMutView64(o);
                FFT_ENGINE.with(|e| {
                    e.borrow_mut()
                        .discard_wop_pbs_lwe_ciphertext(&mut o1, &a1, bsk, ksk, luts, 
                                                        cbs_level_count, cbs_base_log,
                                                        cbs_pfpksk, number_of_bits_of_message_including_padding)
                        .unwrap();
                });
            });
    }
}
