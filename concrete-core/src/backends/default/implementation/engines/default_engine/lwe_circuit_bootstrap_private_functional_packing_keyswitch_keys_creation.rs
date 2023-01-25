use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32,
};
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, GlweSize, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64, LweSize, PolynomialSize};
use crate::specification::engines::{LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError};
use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList as ImplLwePrivateFunctionalPackingKeyswitchKeyList;

impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<Vec<u32>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32> for DefaultEngine {
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32
            (ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            lwe_size.to_lwe_dimension(),
            glwe_size.to_glwe_dimension(),
            poly_size,
            key_count,
        ))
    }
}

impl<'data> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<&'data mut [u32], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'data>>
    for DefaultEngine
{
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'data>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>>
    {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'data> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32(ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            lwe_size.to_lwe_dimension(),
            glwe_size.to_glwe_dimension(),
            poly_size,
            key_count,
        ))
    }
}

impl<'data> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<&'data [u32], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'data>>
    for DefaultEngine
{
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'data>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            32,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32<'data> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView32(ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            lwe_size.to_lwe_dimension(),
            glwe_size.to_glwe_dimension(),
            poly_size,
            key_count,
        ))
    }
}

impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<Vec<u64>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64> for DefaultEngine {
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
            (ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
                container,
                decomposition_base_log,
                decomposition_level_count,
                lwe_size.to_lwe_dimension(),
                glwe_size.to_glwe_dimension(),
                poly_size,
                key_count,
            ))
    }
}

impl<'data> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<&'data mut [u64], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'data>>
for DefaultEngine
{
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'data>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>>
    {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'data> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64(ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            lwe_size.to_lwe_dimension(),
            glwe_size.to_glwe_dimension(),
            poly_size,
            key_count,
        ))
    }
}

impl<'data> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationEngine<&'data [u64], LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'data>>
for DefaultEngine
{
    fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Result<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'data>, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            lwe_size,
            glwe_size,
            poly_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
            64,
        )?;

        Ok(unsafe {
            self.create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
                container,
                lwe_size,
                glwe_size,
                poly_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
        })
    }

    unsafe fn create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        key_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64<'data> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysView64(ImplLwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            container,
            decomposition_base_log,
            decomposition_level_count,
            lwe_size.to_lwe_dimension(),
            glwe_size.to_glwe_dimension(),
            poly_size,
            key_count,
        ))
    }
}

