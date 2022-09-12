use crate::generation::prototyping::PrototypesLweSeededCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweSeededCiphertextArrayEntity;

/// A trait allowing to synthesize an actual LweSeededCiphertextArrayEntity from a prototype.
pub trait SynthesizesLweSeededCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    LweSeededCiphertextArray,
>: PrototypesLweSeededCiphertextArray<Precision, KeyDistribution> where
    LweSeededCiphertextArray: LweSeededCiphertextArrayEntity,
{
    fn synthesize_lwe_seeded_ciphertext_array(
        &mut self,
        prototype: &Self::LweSeededCiphertextArrayProto,
    ) -> LweSeededCiphertextArray;
    fn unsynthesize_lwe_seeded_ciphertext_array(
        &mut self,
        entity: LweSeededCiphertextArray,
    ) -> Self::LweSeededCiphertextArrayProto;
    fn destroy_lwe_seeded_ciphertext_array(&mut self, entity: LweSeededCiphertextArray);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryLweSeededCiphertextArray32, ProtoBinaryLweSeededCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesLweSeededCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweSeededCiphertextArray32, LweSeededCiphertextArray64};

    impl
        SynthesizesLweSeededCiphertextArray<
            Precision32,
            BinaryKeyDistribution,
            LweSeededCiphertextArray32,
        > for Maker
    {
        fn synthesize_lwe_seeded_ciphertext_array(
            &mut self,
            prototype: &Self::LweSeededCiphertextArrayProto,
        ) -> LweSeededCiphertextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext_array(
            &mut self,
            entity: LweSeededCiphertextArray32,
        ) -> Self::LweSeededCiphertextArrayProto {
            ProtoBinaryLweSeededCiphertextArray32(entity)
        }

        fn destroy_lwe_seeded_ciphertext_array(&mut self, _entity: LweSeededCiphertextArray32) {}
    }

    impl
        SynthesizesLweSeededCiphertextArray<
            Precision64,
            BinaryKeyDistribution,
            LweSeededCiphertextArray64,
        > for Maker
    {
        fn synthesize_lwe_seeded_ciphertext_array(
            &mut self,
            prototype: &Self::LweSeededCiphertextArrayProto,
        ) -> LweSeededCiphertextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext_array(
            &mut self,
            entity: LweSeededCiphertextArray64,
        ) -> Self::LweSeededCiphertextArrayProto {
            ProtoBinaryLweSeededCiphertextArray64(entity)
        }

        fn destroy_lwe_seeded_ciphertext_array(&mut self, _entity: LweSeededCiphertextArray64) {}
    }
}
