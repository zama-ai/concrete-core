use crate::generation::prototyping::PrototypesLweSeededKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweSeededKeyswitchKeyEntity;

pub trait SynthesizesLweSeededKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    LweSeededKeyswitchKey,
>: PrototypesLweSeededKeyswitchKey<Precision, InputKeyDistribution, OutputKeyDistribution> where
    LweSeededKeyswitchKey: LweSeededKeyswitchKeyEntity,
{
    fn synthesize_lwe_seeded_keyswitch_key(
        &mut self,
        prototype: &Self::LweSeededKeyswitchKeyProto,
    ) -> LweSeededKeyswitchKey;
    fn unsynthesize_lwe_seeded_keyswitch_key(
        &mut self,
        entity: LweSeededKeyswitchKey,
    ) -> Self::LweSeededKeyswitchKeyProto;
    fn destroy_lwe_seeded_keyswitch_key(&mut self, entity: LweSeededKeyswitchKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweSeededKeyswitchKey32, ProtoBinaryBinaryLweSeededKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweSeededKeyswitchKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweSeededKeyswitchKey32, LweSeededKeyswitchKey64};

    impl
        SynthesizesLweSeededKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweSeededKeyswitchKey32,
        > for Maker
    {
        fn synthesize_lwe_seeded_keyswitch_key(
            &mut self,
            prototype: &Self::LweSeededKeyswitchKeyProto,
        ) -> LweSeededKeyswitchKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_keyswitch_key(
            &mut self,
            entity: LweSeededKeyswitchKey32,
        ) -> Self::LweSeededKeyswitchKeyProto {
            ProtoBinaryBinaryLweSeededKeyswitchKey32(entity)
        }

        fn destroy_lwe_seeded_keyswitch_key(&mut self, _entity: LweSeededKeyswitchKey32) {}
    }

    impl
        SynthesizesLweSeededKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweSeededKeyswitchKey64,
        > for Maker
    {
        fn synthesize_lwe_seeded_keyswitch_key(
            &mut self,
            prototype: &Self::LweSeededKeyswitchKeyProto,
        ) -> LweSeededKeyswitchKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_keyswitch_key(
            &mut self,
            entity: LweSeededKeyswitchKey64,
        ) -> Self::LweSeededKeyswitchKeyProto {
            ProtoBinaryBinaryLweSeededKeyswitchKey64(entity)
        }

        fn destroy_lwe_seeded_keyswitch_key(&mut self, _entity: LweSeededKeyswitchKey64) {}
    }
}
