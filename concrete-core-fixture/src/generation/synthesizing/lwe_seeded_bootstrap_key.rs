use crate::generation::prototyping::PrototypesLweSeededBootstrapKey;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweSeededBootstrapKeyEntity;

/// A trait allowing to synthesize an actual LweSeededBootstrapKeyEntity from a prototype.
pub trait SynthesizesLweSeededBootstrapKey<Precision: IntegerPrecision, LweSeededBootstrapKey>:
    PrototypesLweSeededBootstrapKey<
    Precision,
    LweSeededBootstrapKey::InputKeyDistribution,
    LweSeededBootstrapKey::OutputKeyDistribution,
>
where
    LweSeededBootstrapKey: LweSeededBootstrapKeyEntity,
{
    fn synthesize_lwe_seeded_bootstrap_key(
        &mut self,
        prototype: &Self::LweSeededBootstrapKeyProto,
    ) -> LweSeededBootstrapKey;
    fn unsynthesize_lwe_seeded_bootstrap_key(
        &mut self,
        entity: LweSeededBootstrapKey,
    ) -> Self::LweSeededBootstrapKeyProto;
    fn destroy_lwe_seeded_bootstrap_key(&mut self, entity: LweSeededBootstrapKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweSeededBootstrapKey32, ProtoBinaryBinaryLweSeededBootstrapKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweSeededBootstrapKey;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweSeededBootstrapKey32, LweSeededBootstrapKey64};

    impl SynthesizesLweSeededBootstrapKey<Precision32, LweSeededBootstrapKey32> for Maker {
        fn synthesize_lwe_seeded_bootstrap_key(
            &mut self,
            prototype: &Self::LweSeededBootstrapKeyProto,
        ) -> LweSeededBootstrapKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_bootstrap_key(
            &mut self,
            entity: LweSeededBootstrapKey32,
        ) -> Self::LweSeededBootstrapKeyProto {
            ProtoBinaryBinaryLweSeededBootstrapKey32(entity)
        }

        fn destroy_lwe_seeded_bootstrap_key(&mut self, _entity: LweSeededBootstrapKey32) {}
    }

    impl SynthesizesLweSeededBootstrapKey<Precision64, LweSeededBootstrapKey64> for Maker {
        fn synthesize_lwe_seeded_bootstrap_key(
            &mut self,
            prototype: &Self::LweSeededBootstrapKeyProto,
        ) -> LweSeededBootstrapKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_bootstrap_key(
            &mut self,
            entity: LweSeededBootstrapKey64,
        ) -> Self::LweSeededBootstrapKeyProto {
            ProtoBinaryBinaryLweSeededBootstrapKey64(entity)
        }

        fn destroy_lwe_seeded_bootstrap_key(&mut self, _entity: LweSeededBootstrapKey64) {}
    }
}
