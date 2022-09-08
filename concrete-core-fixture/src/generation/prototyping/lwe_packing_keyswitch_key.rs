use crate::generation::prototypes::{
    LwePackingKeyswitchKeyPrototype, ProtoBinaryBinaryLwePackingKeyswitchKey32,
    ProtoBinaryBinaryLwePackingKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LwePackingKeyswitchKeyGenerationEngine, Variance,
};

use super::PrototypesGlweSecretKey;

/// A trait allowing to manipulate packing keyswitch key prototypes.
pub trait PrototypesLwePackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesGlweSecretKey<Precision, OutputKeyDistribution>
{
    type PackingKeyswitchKeyProto: LwePackingKeyswitchKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_packing_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<
            Precision,
            InputKeyDistribution,
        >>::LweSecretKeyProto,
        output_key: &<Self as PrototypesGlweSecretKey<
            Precision,
            OutputKeyDistribution,
        >>::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::PackingKeyswitchKeyProto;
}

impl PrototypesLwePackingKeyswitchKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type PackingKeyswitchKeyProto = ProtoBinaryBinaryLwePackingKeyswitchKey32;

    fn new_lwe_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::PackingKeyswitchKeyProto {
        ProtoBinaryBinaryLwePackingKeyswitchKey32(
            self.default_engine
                .generate_new_lwe_packing_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_level,
                    decomposition_base_log,
                    noise,
                )
                .unwrap(),
        )
    }
}

impl PrototypesLwePackingKeyswitchKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type PackingKeyswitchKeyProto = ProtoBinaryBinaryLwePackingKeyswitchKey64;

    fn new_lwe_packing_keyswitch_key(
        &mut self,
        input_key: &Self::LweSecretKeyProto,
        output_key: &Self::GlweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::PackingKeyswitchKeyProto {
        ProtoBinaryBinaryLwePackingKeyswitchKey64(
            self.default_engine
                .generate_new_lwe_packing_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    decomposition_level,
                    decomposition_base_log,
                    noise,
                )
                .unwrap(),
        )
    }
}
