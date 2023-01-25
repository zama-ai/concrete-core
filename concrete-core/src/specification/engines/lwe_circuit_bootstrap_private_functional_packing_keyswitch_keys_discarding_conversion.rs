use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount};
use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity;

engine_error! {
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError for
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

impl<EngineError: std::error::Error> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }

        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }

        if decomposition_level_count.0 * decomposition_base_log.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }

        Ok(())
    }
}

/// A trait for engines converting (discarding) LWE bootstrap keys .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE bootstrap key with
/// the conversion of the `input` LWE bootstrap key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
    Output: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    /// Converts a LWE bootstrap key .
    fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE bootstrap key .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
