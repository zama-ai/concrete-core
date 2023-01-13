use crate::prelude::{LweKeyswitchKeyEntity, MessageBitsCount};
use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweBootstrapKeyEntity, LweCiphertextVectorEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, PlaintextVectorEntity,
};
use crate::specification::parameters::{DecompositionBaseLog, DecompositionLevelCount};

engine_error! {
    LweCiphertextVectorDiscardingWopPbsError for
    LweCiphertextVectorDiscardingWopPbsEngine @
    NullDecompositionBaseLog => "The circuit bootstrap decomposition base log must be greater \
                                than zero.",
    NullDecompositionLevelCount => "The circuit bootstrap decomposition level count must be \
                                    greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    KeysLweDimensionMismatch => "The bootstrap key output LWE dimension must be the same as the \
                                input LWE dimension of the circuit bootstrap private functional \
                                packing keyswitch keys.",
    InputLweDimensionMismatch => "The input ciphertexts LWE dimension must be the same as the \
                                    bootstrap key input LWE dimension.",
    OutputLweDimensionMismatch => "The output ciphertexts LWE dimension must be the same as the \
                                    `cbs_pfpksk` output GLWE dimension times its output polynomial \
                                    size.",
    MalformedLookUpTables => "The input `luts` must have a size divisible by the circuit bootstrap \
                                private functional packing keyswitch keys output polynomial size \
                                times the number of output ciphertexts. This is required to get \
                                small look-up tables of polynomials of the same size for each \
                                output ciphertext.",
    InvalidSmallLookUpTableSize => "The number of polynomials times the polynomial size in a small \
                                    look-up table must be equal to 2 to the power the number of \
                                    input ciphertexts encrypting bits."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorDiscardingWopPbsError<EngineError>
{
    /// Validates the inputs
    #[allow(clippy::too_many_arguments)]
    pub fn perform_generic_checks<
        Input: LweCiphertextVectorEntity,
        Output: LweCiphertextVectorEntity,
        BootstrapKey: LweBootstrapKeyEntity,
        KeyswitchKey: LweKeyswitchKeyEntity,
        LUTs: PlaintextVectorEntity,
        CBSPFPKSK: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    >(
        input: &Input,
        output: &Output,
        bsk: &BootstrapKey,
        _ksk: &KeyswitchKey,
        luts: &LUTs,
        cbs_decomposition_level_count: DecompositionLevelCount,
        cbs_decomposition_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CBSPFPKSK,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if bsk.output_lwe_dimension() != cbs_pfpksk.input_lwe_dimension() {
            return Err(Self::KeysLweDimensionMismatch);
        }
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if output.lwe_dimension().0
            != cbs_pfpksk.output_glwe_dimension().0 * cbs_pfpksk.output_polynomial_size().0
        {
            return Err(Self::OutputLweDimensionMismatch);
        }

        let lut_polynomial_size = cbs_pfpksk.output_polynomial_size().0;
        if luts.plaintext_count().0 % (lut_polynomial_size * output.lwe_ciphertext_count().0) != 0 {
            return Err(Self::MalformedLookUpTables);
        }

        let small_lut_size = luts.plaintext_count().0 / output.lwe_ciphertext_count().0;
        if small_lut_size < lut_polynomial_size {
            return Err(Self::InvalidSmallLookUpTableSize);
        }

        if cbs_decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }
        if cbs_decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }
        if cbs_decomposition_base_log.0 * cbs_decomposition_level_count.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines performing a (discarding) wop PBS on LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation performs the wop PBS.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingWopPbsEngine<
    Input,
    Output,
    BootstrapKey,
    KeyswitchKey,
    LUTs,
    CircuitBootstrapFunctionalPackingKeyswitchKeys,
>: AbstractEngine where
    Input: LweCiphertextVectorEntity,
    Output: LweCiphertextVectorEntity,
    BootstrapKey: LweBootstrapKeyEntity,
    KeyswitchKey: LweKeyswitchKeyEntity,
    LUTs: PlaintextVectorEntity,
    CircuitBootstrapFunctionalPackingKeyswitchKeys:
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    /// Performs the circuit bootstrapping on all boolean input LWE ciphertexts followed by vertical
    /// packing using the provided look-up table.
    #[allow(clippy::too_many_arguments)]
    fn discard_wop_pbs_lwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        luts: &LUTs,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CircuitBootstrapFunctionalPackingKeyswitchKeys,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingWopPbsError<Self::EngineError>,
    >;

    /// Unsafely performs the wop PBS on all input LWE ciphertexts.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingWopPbsError`]. For safety
    /// concerns _specific_ to an engine, refer to the implementer safety section.
    #[allow(clippy::too_many_arguments)]
    unsafe fn discard_wop_pbs_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
        bsk: &BootstrapKey,
        ksk: &KeyswitchKey,
        luts: &LUTs,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &CircuitBootstrapFunctionalPackingKeyswitchKeys,
        number_of_bits_of_message_including_padding: MessageBitsCount,
    );
}
