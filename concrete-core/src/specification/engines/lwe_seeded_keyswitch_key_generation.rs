use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};
use crate::specification::entities::{LweSecretKeyEntity, LweSeededKeyswitchKeyEntity};

engine_error! {
    LweSeededKeyswitchKeyGenerationError for LweSeededKeyswitchKeyGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

impl<EngineError: std::error::Error> LweSeededKeyswitchKeyGenerationError<EngineError> {
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

/// A trait for engines generating new seeded LWE keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new seeded LWE keyswitch key
/// allowing to switch from the `input_key` LWE secret key to the `output_key` LWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::LweSeededKeyswitchKeyEntity`)
pub trait LweSeededKeyswitchKeyGenerationEngine<InputSecretKey, OutputSecretKey, SeededKeyswitchKey>:
    AbstractEngine
where
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: LweSecretKeyEntity,
    SeededKeyswitchKey: LweSeededKeyswitchKeyEntity,
{
    /// Generates a new seeded LWE keyswitch key.
    fn generate_new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<SeededKeyswitchKey, LweSeededKeyswitchKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates a new seeded LWE keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededKeyswitchKeyGenerationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn generate_new_lwe_seeded_keyswitch_key_unchecked(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> SeededKeyswitchKey;
}
