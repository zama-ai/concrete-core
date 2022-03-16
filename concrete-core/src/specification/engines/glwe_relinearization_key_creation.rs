use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweSecretKeyEntity, GlweRelinearizationKeyEntity,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

engine_error! {
    GlweRelinearizationKeyCreationError for GlweRelinearizationKeyCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

impl<EngineError: std::error::Error> GlweRelinearizationKeyCreationError<EngineError> {
    pub fn perform_generic_checks(
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        integer_precision: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > integer_precision {
            return Err(Self::DecompositionTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines creating GLWE relinearization keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates a GLWE relinearization key from the
/// `input_key` GLWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::GlweRelinearizationKeyEntity`)
pub trait GlweRelinearizationKeyCreationEngine<GlweSecretKey, RelinearizationKey>:
    AbstractEngine
where
    RelinearizationKey: GlweRelinearizationKeyEntity,
    GlweSecretKey: GlweSecretKeyEntity<KeyDistribution = RelinearizationKey::KeyDistribution>,
{
    /// Creates a GLWE relinearization key.
    fn create_glwe_relinearization_key(
        &mut self,
        input_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<RelinearizationKey, GlweRelinearizationKeyCreationError<Self::EngineError>>;

    /// Unsafely creates a GLWE relinearization key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweRelinearizationKeyCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_glwe_relinearization_key_unchecked(
        &mut self,
        input_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> RelinearizationKey;
}
