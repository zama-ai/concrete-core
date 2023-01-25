use crate::backends::default::engines::DefaultEngine;
use crate::backends::default::entities::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32,
};
use crate::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::prelude::{LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64};
use crate::specification::engines::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError,
};

impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'_>>
    for DefaultEngine
{
    fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        output: &mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'_>,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> Result<(), LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError
        ::perform_generic_checks(output.decomposition_level_count(), input.decomposition_base_log
        (), 32)?;
        unsafe { self.discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        output: &mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView32<'_>,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine<LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'_>>
for DefaultEngine
{
    fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        output: &mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'_>,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<(), LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError<Self::EngineError>> {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionError
        ::perform_generic_checks(output.decomposition_level_count(), input.decomposition_base_log
        (), 64)?;
        unsafe { self.discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        output: &mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64<'_>,
        input: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}
