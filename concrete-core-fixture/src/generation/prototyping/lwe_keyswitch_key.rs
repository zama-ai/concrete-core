use crate::generation::prototypes::{
    LweKeyswitchKeyPrototype, ProtoBinaryBinaryLweKeyswitchKey32,
    ProtoBinaryBinaryLweKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweKeyswitchKeyGenerationEngine, Variance,
};

/// A trait allowing to manipulate lwe keyswitch key prototypes.
pub trait PrototypesLweKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, InputKeyDistribution>
    + PrototypesLweSecretKey<Precision, OutputKeyDistribution>
{
    type LweKeyswitchKeyProto: LweKeyswitchKeyPrototype<
        Precision = Precision,
        InputKeyDistribution = InputKeyDistribution,
        OutputKeyDistribution = OutputKeyDistribution,
    >;
    fn new_lwe_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision, InputKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision, OutputKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweKeyswitchKeyProto;
}

impl PrototypesLweKeyswitchKey<Precision32, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweKeyswitchKeyProto = ProtoBinaryBinaryLweKeyswitchKey32;

    fn new_lwe_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision32, BinaryKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision32, BinaryKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweKeyswitchKeyProto {
        ProtoBinaryBinaryLweKeyswitchKey32(
            self.default_engine
                .generate_new_lwe_keyswitch_key(
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

impl PrototypesLweKeyswitchKey<Precision64, BinaryKeyDistribution, BinaryKeyDistribution>
    for Maker
{
    type LweKeyswitchKeyProto = ProtoBinaryBinaryLweKeyswitchKey64;

    fn new_lwe_keyswitch_key(
        &mut self,
        input_key: &<Self as PrototypesLweSecretKey<Precision64, BinaryKeyDistribution>>::LweSecretKeyProto,
        output_key: &<Self as PrototypesLweSecretKey<Precision64, BinaryKeyDistribution>>::LweSecretKeyProto,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Self::LweKeyswitchKeyProto {
        ProtoBinaryBinaryLweKeyswitchKey64(
            self.default_engine
                .generate_new_lwe_keyswitch_key(
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
