use super::engine_error;
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweSize, LweSize, PolynomialSize};
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity;

engine_error! {
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError for LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullKeyCount => "The key count must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    InvalidContainerSize => "The length of the container used to create the LWE CBS PFPKS keys \
                              needs to be a multiple of \
                              `decomposition_level_count * lwe_size * glwe_size * poly_size * \
                              key_count`."
}

impl<EngineError: std::error::Error> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<EngineError> {
    pub fn perform_generic_checks(
        container_length: usize,
        input_lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }
        if key_count.0 == 0 {
            return Err(Self::NullKeyCount);
        }
        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }
        if container_length
            % (decomposition_level_count.0 * glwe_size.0 * key_count.0 * poly_size.0 * 
            input_lwe_size.0)
            != 0
        {
            return Err(Self::InvalidContainerSize);
        }
        Ok(())
    }
}

pub trait LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<Container, BootstrapKey>: AbstractEngine
where
    BootstrapKey: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: Container,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<BootstrapKey, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>>;

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: Container,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> BootstrapKey;
}
