use crate::generation::prototyping::PrototypesLweSecretKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweSecretKeyEntity;

/// A trait allowing to synthesize an actual lwe secret key vector entity from a prototype.
pub trait SynthesizesLweSecretKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    LweSecretKey,
>: PrototypesLweSecretKey<Precision, KeyDistribution> where
    LweSecretKey: LweSecretKeyEntity,
{
    fn synthesize_lwe_secret_key(&mut self, prototype: &Self::LweSecretKeyProto) -> LweSecretKey;
    fn unsynthesize_lwe_secret_key(&mut self, entity: LweSecretKey) -> Self::LweSecretKeyProto;
    fn destroy_lwe_secret_key(&mut self, entity: LweSecretKey);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64};
    use crate::generation::synthesizing::SynthesizesLweSecretKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweSecretKey32, LweSecretKey64};

    impl SynthesizesLweSecretKey<Precision32, BinaryKeyDistribution, LweSecretKey32> for Maker {
        fn synthesize_lwe_secret_key(
            &mut self,
            prototype: &Self::LweSecretKeyProto,
        ) -> LweSecretKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_secret_key(
            &mut self,
            entity: LweSecretKey32,
        ) -> Self::LweSecretKeyProto {
            ProtoBinaryLweSecretKey32(entity)
        }

        fn destroy_lwe_secret_key(&mut self, _entity: LweSecretKey32) {}
    }

    impl SynthesizesLweSecretKey<Precision64, BinaryKeyDistribution, LweSecretKey64> for Maker {
        fn synthesize_lwe_secret_key(
            &mut self,
            prototype: &Self::LweSecretKeyProto,
        ) -> LweSecretKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_secret_key(
            &mut self,
            entity: LweSecretKey64,
        ) -> Self::LweSecretKeyProto {
            ProtoBinaryLweSecretKey64(entity)
        }

        fn destroy_lwe_secret_key(&mut self, _entity: LweSecretKey64) {}
    }
}
