use super::engine_error;
use crate::prelude::{
    CleartextVectorEntity, FunctionalPackingKeyswitchKeyEntity, GlweSecretKeyEntity,
};
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::dispersion::StandardDev;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

//TODO:
engine_error! {
    FunctionalPackingKeyswitchKeyCreationError for FunctionalPackingKeyswitchKeyCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

//TODO:
impl<EngineError: std::error::Error> FunctionalPackingKeyswitchKeyCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        integer_precision: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }

        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }

        if decomposition_level_count.0 * decomposition_base_log.0 > integer_precision {
            return Err(Self::DecompositionTooLarge);
        }

        Ok(())
    }
}

/// A trait for engines creating LWE functional packing keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE functional packing keyswitch key
/// allowing to switch from the `input_key` LWE secret key to the `output_key` GLWE secret key.
///
/// # Formal Definition
pub trait FunctionalPackingKeyswitchKeyCreationEngine<
    InputSecretKey,
    OutputSecretKey,
    FunctionalPackingKeyswitchKey,
    CleartextVector,
    Raw,
>: AbstractEngine where
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: GlweSecretKeyEntity,
    CleartextVector: CleartextVectorEntity,
    FunctionalPackingKeyswitchKey: FunctionalPackingKeyswitchKeyEntity<
        InputKeyDistribution = InputSecretKey::KeyDistribution,
        OutputKeyDistribution = OutputSecretKey::KeyDistribution,
    >,
{
    /// Creates a functional packing keyswitch key.
    fn create_functional_packing_keyswitch_key<F: Fn(Raw) -> Raw>(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector,
    ) -> Result<
        FunctionalPackingKeyswitchKey,
        FunctionalPackingKeyswitchKeyCreationError<Self::EngineError>,
    >;

    /// Unsafely creates a functional packing keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`FunctionalPackingKeyswitchKeyCreationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn create_functional_packing_keyswitch_key_unchecked<F: Fn(Raw) -> Raw>(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: F,
        polynomial: &CleartextVector,
    ) -> FunctionalPackingKeyswitchKey;
}
