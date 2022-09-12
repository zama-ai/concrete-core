use crate::generation::prototyping::PrototypesLwePackingKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LwePackingKeyswitchKeyEntity;

pub trait SynthesizesPackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    LwePackingKeyswitchKey,
>:
    PrototypesLwePackingKeyswitchKey<Precision, InputKeyDistribution, OutputKeyDistribution> where
    LwePackingKeyswitchKey: LwePackingKeyswitchKeyEntity,
{
    fn synthesize_packing_keyswitch_key(
        &mut self,
        prototype: &Self::PackingKeyswitchKeyProto,
    ) -> LwePackingKeyswitchKey;
    fn unsynthesize_packing_keyswitch_key(
        &mut self,
        entity: LwePackingKeyswitchKey,
    ) -> Self::PackingKeyswitchKeyProto;
    fn destroy_packing_keyswitch_key(&mut self, entity: LwePackingKeyswitchKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLwePackingKeyswitchKey32, ProtoBinaryBinaryLwePackingKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesPackingKeyswitchKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LwePackingKeyswitchKey32, LwePackingKeyswitchKey64};

    impl
        SynthesizesPackingKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LwePackingKeyswitchKey32,
        > for Maker
    {
        fn synthesize_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PackingKeyswitchKeyProto,
        ) -> LwePackingKeyswitchKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_packing_keyswitch_key(
            &mut self,
            entity: LwePackingKeyswitchKey32,
        ) -> Self::PackingKeyswitchKeyProto {
            ProtoBinaryBinaryLwePackingKeyswitchKey32(entity)
        }

        fn destroy_packing_keyswitch_key(&mut self, _entity: LwePackingKeyswitchKey32) {}
    }

    impl
        SynthesizesPackingKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LwePackingKeyswitchKey64,
        > for Maker
    {
        fn synthesize_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PackingKeyswitchKeyProto,
        ) -> LwePackingKeyswitchKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_packing_keyswitch_key(
            &mut self,
            entity: LwePackingKeyswitchKey64,
        ) -> Self::PackingKeyswitchKeyProto {
            ProtoBinaryBinaryLwePackingKeyswitchKey64(entity)
        }

        fn destroy_packing_keyswitch_key(&mut self, _entity: LwePackingKeyswitchKey64) {}
    }
}
