pub use crate::generation::prototypes::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysPrototype,
    ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::Variance;

use super::PrototypesGlweSecretKey;
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine,
};

/// A trait allowing to manipulate prototypes of private functional packing keyswitch keys array
/// used in circuit bootstrapping.
pub trait PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
{
    type LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_lwe_key: &<Self as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::LweSecretKeyProto,
        output_glwe_key: &<Self as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::GlweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto;
}

impl
    PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
        Precision32,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto =
        ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32;

    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_lwe_key: &<Self as PrototypesLweSecretKey<
            Precision32,
            BinaryKeyDistribution,
        >>::LweSecretKeyProto,
        output_glwe_key: &<Self as PrototypesGlweSecretKey<
            Precision32,
            BinaryKeyDistribution,
        >>::GlweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto {
        ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
            self.default_engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                    &input_lwe_key.0,
                    &output_glwe_key.0,
                    decomposition_base_log,
                    decomposition_level_count,
                    noise,
                )
                .unwrap(),
        )
    }
}

impl
    PrototypesLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys<
        Precision64,
        BinaryKeyDistribution,
        BinaryKeyDistribution,
    > for Maker
{
    type LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto =
        ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64;

    fn new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_lwe_key: &<Self as PrototypesLweSecretKey<
            Precision64,
            BinaryKeyDistribution,
        >>::LweSecretKeyProto,
        output_glwe_key: &<Self as PrototypesGlweSecretKey<
            Precision64,
            BinaryKeyDistribution,
        >>::GlweSecretKeyProto,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Self::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysProto {
        ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
            self.default_engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                    &input_lwe_key.0,
                    &output_glwe_key.0,
                    decomposition_base_log,
                    decomposition_level_count,
                    noise,
                )
                .unwrap(),
        )
    }
}
