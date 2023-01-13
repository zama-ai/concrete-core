use crate::prelude::{FftError, FftFourierLweBootstrapKey64, DecompositionBaseLog, DecompositionLevelCount, LweBootstrapKeyEntity, LweCiphertextDiscardingWopPbsEngine, LweCiphertextDiscardingWopPbsError, MessageBitsCount, FftEngine, LweCiphertext64, LweKeyswitchKey64, PlaintextVector64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCiphertextEntity, LweKeyswitchKeyEntity, CiphertextCount, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, DeltaLog, ExtractedBitsCount, LweCiphertextMutView64, LweCiphertextView64};
use crate::commons::math::tensor::{AsRefSlice, AsMutSlice, AsRefTensor, AsMutTensor};
use crate::backends::fft::private::crypto::wop_pbs::{circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch, extract_bits, extract_bits_scratch};
use crate::backends::fft::private::math::fft::Fft;
use crate::commons::crypto::lwe::LweList;
use crate::commons::math::polynomial::PolynomialList;

impl From<FftError>
    for LweCiphertextDiscardingWopPbsError<FftError>
{
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextDiscardingWopPbsEngine<
        LweCiphertext64,
        LweCiphertext64,
        FftFourierLweBootstrapKey64,
        LweKeyswitchKey64,
        PlaintextVector64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for FftEngine
{
    fn discard_wop_pbs_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) -> Result<
        (),
        LweCiphertextDiscardingWopPbsError<Self::EngineError>,
    > {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingWopPbsError::
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
            self.discard_wop_pbs_lwe_ciphertext_unchecked(
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

    unsafe fn discard_wop_pbs_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) {
        let lut_as_polynomial_list =
            PolynomialList::from_container(luts.0.as_tensor().as_slice(), bsk.polynomial_size());

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u64>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );
        let mut bit_extract_output = LweList::allocate(0_u64, input.lwe_dimension().to_lwe_size(), 
                                                   CiphertextCount
                                                       (number_of_bits_of_message_including_padding.0));
        extract_bits(
            bit_extract_output.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            DeltaLog(64 - number_of_bits_of_message_including_padding.0),
            ExtractedBitsCount(number_of_bits_of_message_including_padding.0),
            fft,
            self.stack(),
        );
        self.resize(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                CiphertextCount(number_of_bits_of_message_including_padding.0),
                CiphertextCount(1),
                input.lwe_dimension().to_lwe_size(),
                lut_as_polynomial_list.polynomial_count(),
                bsk.output_lwe_dimension().to_lwe_size(),
                cbs_pfpksk.output_polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                cbs_level_count,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );
        let mut out_list = LweList::from_container(
            output.0.as_mut_tensor().as_mut_slice(),
            input.lwe_dimension().to_lwe_size());
        circuit_bootstrap_boolean_vertical_packing(
            lut_as_polynomial_list.as_view(),
            bsk.0.as_view(),
            out_list.as_mut_view(),
            bit_extract_output.as_view(),
            cbs_pfpksk.0.as_view(),
            cbs_level_count,
            cbs_base_log,
            fft,
            self.stack(),
        );
    }
}

impl
LweCiphertextDiscardingWopPbsEngine<
    LweCiphertextView64<'_>,
    LweCiphertextMutView64<'_>,
    FftFourierLweBootstrapKey64,
    LweKeyswitchKey64,
    PlaintextVector64,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
> for FftEngine
{
    fn discard_wop_pbs_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) -> Result<
        (),
        LweCiphertextDiscardingWopPbsError<Self::EngineError>,
    > {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextDiscardingWopPbsError::
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
            self.discard_wop_pbs_lwe_ciphertext_unchecked(
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

    unsafe fn discard_wop_pbs_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
        bsk: &FftFourierLweBootstrapKey64,
        ksk: &LweKeyswitchKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) {
        let lut_as_polynomial_list =
            PolynomialList::from_container(luts.0.as_tensor().as_slice(), bsk.polynomial_size());

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            extract_bits_scratch::<u64>(
                input.lwe_dimension(),
                ksk.output_lwe_dimension(),
                bsk.glwe_dimension().to_glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );
        let mut bit_extract_output = LweList::allocate(0_u64, input.lwe_dimension().to_lwe_size(),
                                                       CiphertextCount
                                                           (number_of_bits_of_message_including_padding.0));
        extract_bits(
            bit_extract_output.as_mut_view(),
            input.0.as_view(),
            ksk.0.as_view(),
            bsk.0.as_view(),
            DeltaLog(64 - number_of_bits_of_message_including_padding.0),
            ExtractedBitsCount(number_of_bits_of_message_including_padding.0),
            fft,
            self.stack(),
        );
        self.resize(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                CiphertextCount(number_of_bits_of_message_including_padding.0),
                CiphertextCount(1),
                input.lwe_dimension().to_lwe_size(),
                lut_as_polynomial_list.polynomial_count(),
                bsk.output_lwe_dimension().to_lwe_size(),
                cbs_pfpksk.output_polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                cbs_level_count,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );
        let mut out_list = LweList::from_container(
            output.0.as_mut_tensor().as_mut_slice(),
            input.lwe_dimension().to_lwe_size());
        circuit_bootstrap_boolean_vertical_packing(
            lut_as_polynomial_list.as_view(),
            bsk.0.as_view(),
            out_list.as_mut_view(),
            bit_extract_output.as_view(),
            cbs_pfpksk.0.as_view(),
            cbs_level_count,
            cbs_base_log,
            fft,
            self.stack(),
        );
    }
}
