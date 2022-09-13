use crate::generation::prototyping::PrototypesLwePublicKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LwePublicKeyEntity;

/// A trait allowing to synthesize an actual lwe public key vector entity from a prototype.
pub trait SynthesizesLwePublicKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    LwePublicKey,
>: PrototypesLwePublicKey<Precision, KeyDistribution> where
    LwePublicKey: LwePublicKeyEntity,
{
    fn synthesize_lwe_public_key(&mut self, prototype: &Self::LwePublicKeyProto) -> LwePublicKey;
    fn unsynthesize_lwe_public_key(&mut self, entity: LwePublicKey) -> Self::LwePublicKeyProto;
    fn destroy_lwe_public_key(&mut self, entity: LwePublicKey);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryLwePublicKey32, ProtoBinaryLwePublicKey64};
    use crate::generation::synthesizing::SynthesizesLwePublicKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LwePublicKey32, LwePublicKey64};

    impl SynthesizesLwePublicKey<Precision32, BinaryKeyDistribution, LwePublicKey32> for Maker {
        fn synthesize_lwe_public_key(
            &mut self,
            prototype: &Self::LwePublicKeyProto,
        ) -> LwePublicKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_public_key(
            &mut self,
            entity: LwePublicKey32,
        ) -> Self::LwePublicKeyProto {
            ProtoBinaryLwePublicKey32(entity)
        }

        fn destroy_lwe_public_key(&mut self, _entity: LwePublicKey32) {}
    }

    impl SynthesizesLwePublicKey<Precision64, BinaryKeyDistribution, LwePublicKey64> for Maker {
        fn synthesize_lwe_public_key(
            &mut self,
            prototype: &Self::LwePublicKeyProto,
        ) -> LwePublicKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_public_key(
            &mut self,
            entity: LwePublicKey64,
        ) -> Self::LwePublicKeyProto {
            ProtoBinaryLwePublicKey64(entity)
        }

        fn destroy_lwe_public_key(&mut self, _entity: LwePublicKey64) {}
    }
}
