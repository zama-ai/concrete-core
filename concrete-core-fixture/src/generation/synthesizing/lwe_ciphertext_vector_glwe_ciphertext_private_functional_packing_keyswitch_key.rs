use crate::generation::prototyping::PrototypesPrivateFunctionalPackingKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::PrivateFunctionalPackingKeyswitchKeyEntity;

pub trait SynthesizesPrivateFunctionalPackingKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    PrivateFunctionalPackingKeyswitchKey,
>:
    PrototypesPrivateFunctionalPackingKeyswitchKey<
    Precision,
    InputKeyDistribution,
    OutputKeyDistribution,
> where
    PrivateFunctionalPackingKeyswitchKey: PrivateFunctionalPackingKeyswitchKeyEntity,
{
    fn synthesize_private_functional_packing_keyswitch_key(
        &mut self,
        prototype: &Self::PrivateFunctionalPackingKeyswitchKeyProto,
    ) -> PrivateFunctionalPackingKeyswitchKey;
    fn unsynthesize_private_functional_packing_keyswitch_key(
        &mut self,
        entity: PrivateFunctionalPackingKeyswitchKey,
    ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto;
    fn destroy_private_functional_packing_keyswitch_key(
        &mut self,
        entity: PrivateFunctionalPackingKeyswitchKey,
    );
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32,
        ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesPrivateFunctionalPackingKeyswitchKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        PrivateFunctionalPackingKeyswitchKey32, PrivateFunctionalPackingKeyswitchKey64,
    };

    impl
        SynthesizesPrivateFunctionalPackingKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            PrivateFunctionalPackingKeyswitchKey32,
        > for Maker
    {
        fn synthesize_private_functional_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PrivateFunctionalPackingKeyswitchKeyProto,
        ) -> PrivateFunctionalPackingKeyswitchKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_private_functional_packing_keyswitch_key(
            &mut self,
            entity: PrivateFunctionalPackingKeyswitchKey32,
        ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto {
            ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32(entity)
        }

        fn destroy_private_functional_packing_keyswitch_key(
            &mut self,
            _entity: PrivateFunctionalPackingKeyswitchKey32,
        ) {
        }
    }

    impl
        SynthesizesPrivateFunctionalPackingKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            PrivateFunctionalPackingKeyswitchKey64,
        > for Maker
    {
        fn synthesize_private_functional_packing_keyswitch_key(
            &mut self,
            prototype: &Self::PrivateFunctionalPackingKeyswitchKeyProto,
        ) -> PrivateFunctionalPackingKeyswitchKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_private_functional_packing_keyswitch_key(
            &mut self,
            entity: PrivateFunctionalPackingKeyswitchKey64,
        ) -> Self::PrivateFunctionalPackingKeyswitchKeyProto {
            ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64(entity)
        }

        fn destroy_private_functional_packing_keyswitch_key(
            &mut self,
            _entity: PrivateFunctionalPackingKeyswitchKey64,
        ) {
        }
    }
}
