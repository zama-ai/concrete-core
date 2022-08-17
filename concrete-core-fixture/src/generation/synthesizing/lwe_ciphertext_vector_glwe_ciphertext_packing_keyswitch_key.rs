use crate::generation::prototyping::PrototypesPackingKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::PackingKeyswitchKeyEntity;

pub trait SynthesizesPackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    PackingKeyswitchKey,
>: PrototypesPackingKeyswitchKey<Precision, InputKeyDistribution, OutputKeyDistribution> where
    PackingKeyswitchKey: PackingKeyswitchKeyEntity,
{
    fn synthesize_packing_keyswitch_key(
        &mut self,
        prototype: &Self::PackingKeyswitchKeyProto,
    ) -> PackingKeyswitchKey;
    fn unsynthesize_packing_keyswitch_key(
        &mut self,
        entity: PackingKeyswitchKey,
    ) -> Self::PackingKeyswitchKeyProto;
    fn destroy_packing_keyswitch_key(&mut self, entity: PackingKeyswitchKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryPackingKeyswitchKey32, ProtoBinaryBinaryPackingKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesPackingKeyswitchKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{PackingKeyswitchKey32, PackingKeyswitchKey64};

    impl
        SynthesizesPackingKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            PackingKeyswitchKey32,
        > for Maker
    {
        fn synthesize_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PackingKeyswitchKeyProto,
        ) -> PackingKeyswitchKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_packing_keyswitch_key(
            &mut self,
            entity: PackingKeyswitchKey32,
        ) -> Self::PackingKeyswitchKeyProto {
            ProtoBinaryBinaryPackingKeyswitchKey32(entity)
        }

        fn destroy_packing_keyswitch_key(&mut self, _entity: PackingKeyswitchKey32) {}
    }

    impl
        SynthesizesPackingKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            PackingKeyswitchKey64,
        > for Maker
    {
        fn synthesize_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PackingKeyswitchKeyProto,
        ) -> PackingKeyswitchKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_packing_keyswitch_key(
            &mut self,
            entity: PackingKeyswitchKey64,
        ) -> Self::PackingKeyswitchKeyProto {
            ProtoBinaryBinaryPackingKeyswitchKey64(entity)
        }

        fn destroy_packing_keyswitch_key(&mut self, _entity: PackingKeyswitchKey64) {}
    }
}
