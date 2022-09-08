use crate::generation::prototypes::{
    LweSeededKeyswitchKeyPrototype, ProtoBinaryBinaryLweSeededKeyswitchKey32,
    ProtoBinaryBinaryLweSeededKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweSeededKeyswitchKeyGenerationEngine, Variance,
};

/// A trait allowing to manipulate lwe keyswitch key prototypes.
pub trait PrototypesLweSeededKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesLweSecretKey<Precision, OutputKeyDistribution>
{
    type LweSeededKeyswitchKeyProto: LweSeededKeyswitchKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision, OutputKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededKeyswitchKeyProto;
}

impl PrototypesLweSeededKeyswitchKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweSeededKeyswitchKeyProto = ProtoBinaryBinaryLweSeededKeyswitchKey32;

    fn new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision32, BinaryKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision32, BinaryKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededKeyswitchKeyProto {
        ProtoBinaryBinaryLweSeededKeyswitchKey32(
            self.default_engine
                .generate_new_lwe_seeded_keyswitch_key(
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

impl PrototypesLweSeededKeyswitchKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweSeededKeyswitchKeyProto = ProtoBinaryBinaryLweSeededKeyswitchKey64;

    fn new_lwe_seeded_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision64, BinaryKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision64, BinaryKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweSeededKeyswitchKeyProto {
        ProtoBinaryBinaryLweSeededKeyswitchKey64(
            self.default_engine
                .generate_new_lwe_seeded_keyswitch_key(
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
