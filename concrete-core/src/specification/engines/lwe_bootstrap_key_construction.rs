use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweBootstrapKeyEntity;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};

engine_error! {
    LweBootstrapKeyConstructionError for LweBootstrapKeyConstructionEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    InvalidContainerSize => "The length of the container used to create the LWE bootstrap key \
                              needs to be a multiple of \
                              `decomposition_level_count* glwe_size * glwe_size * poly_size`."
}

impl<EngineError: std::error::Error> LweBootstrapKeyConstructionError<EngineError> {
    pub fn perform_generic_checks(
        container_length: usize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
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
        if container_length
            % (decomposition_level_count.0 * glwe_size.0 * glwe_size.0 * poly_size.0)
            != 0
        {
            return Err(Self::InvalidContainerSize);
        }
        Ok(())
    }
}

/// A trait for engines constructing LWE bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation constructs an LWE bootstrap key from the given
/// `container`.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::LweBootstrapKeyEntity`)
pub trait LweBootstrapKeyConstructionEngine<Container, BootstrapKey>: AbstractEngine
where
    BootstrapKey: LweBootstrapKeyEntity,
{
    /// Constructs an LWE bootstrap key.
    fn construct_lwe_bootstrap_key(
        &mut self,
        container: Container,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<BootstrapKey, LweBootstrapKeyConstructionError<Self::EngineError>>;

    /// Unsafely constructs an LWE bootstrap key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyConstructionError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn construct_lwe_bootstrap_key_unchecked(
        &mut self,
        container: Container,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> BootstrapKey;
}
