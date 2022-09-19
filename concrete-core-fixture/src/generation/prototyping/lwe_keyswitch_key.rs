use crate::generation::prototypes::{
    LweKeyswitchKeyPrototype, ProtoBinaryBinaryLweKeyswitchKey32,
    ProtoBinaryBinaryLweKeyswitchKey64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    LweKeyswitchKeyConsumingRetrievalEngine, LweKeyswitchKeyCreationEngine,
    LweKeyswitchKeyGenerationEngine, Variance,
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
    fn transform_raw_vec_to_lwe_keyswitch_key(
        &mut self,
        raw: &[Precision::Raw],
        output_lwe_dimension: LweDimension,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweKeyswitchKeyProto;
    fn transform_lwe_keyswitch_key_to_raw_vec(
        &mut self,
        lwe_keyswitch_key: &Self::LweKeyswitchKeyProto,
    ) -> Vec<Precision::Raw>;
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

    fn transform_raw_vec_to_lwe_keyswitch_key(
        &mut self,
        raw: &[u32],
        output_lwe_dimension: LweDimension,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweKeyswitchKeyProto {
        ProtoBinaryBinaryLweKeyswitchKey32(
            self.default_engine
                .create_lwe_keyswitch_key_from(
                    raw.to_owned(),
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level,
                )
                .unwrap(),
        )
    }

    fn transform_lwe_keyswitch_key_to_raw_vec(
        &mut self,
        lwe_keyswitch_key: &Self::LweKeyswitchKeyProto,
    ) -> Vec<u32> {
        let lwe_keyswitch_key = lwe_keyswitch_key.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_keyswitch_key(lwe_keyswitch_key)
            .unwrap()
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

    fn transform_raw_vec_to_lwe_keyswitch_key(
        &mut self,
        raw: &[u64],
        output_lwe_dimension: LweDimension,
        decomposition_level: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::LweKeyswitchKeyProto {
        ProtoBinaryBinaryLweKeyswitchKey64(
            self.default_engine
                .create_lwe_keyswitch_key_from(
                    raw.to_owned(),
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level,
                )
                .unwrap(),
        )
    }

    fn transform_lwe_keyswitch_key_to_raw_vec(
        &mut self,
        lwe_keyswitch_key: &Self::LweKeyswitchKeyProto,
    ) -> Vec<u64> {
        let lwe_keyswitch_key = lwe_keyswitch_key.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_keyswitch_key(lwe_keyswitch_key)
            .unwrap()
    }
}
