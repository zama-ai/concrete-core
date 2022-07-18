use crate::generation::prototyping::PrototypesLweSeededCiphertextVector;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweSeededCiphertextVectorEntity;

/// A trait allowing to synthesize an actual LweSeededCiphertextVectorEntity from a prototype.
pub trait SynthesizesLweSeededCiphertextVector<
    Precision: IntegerPrecision,
    LweSeededCiphertextVector,
>:
    PrototypesLweSeededCiphertextVector<Precision, LweSeededCiphertextVector::KeyDistribution> where
    LweSeededCiphertextVector: LweSeededCiphertextVectorEntity,
{
    fn synthesize_lwe_seeded_ciphertext_vector(
        &mut self,
        prototype: &Self::LweSeededCiphertextVectorProto,
    ) -> LweSeededCiphertextVector;
    fn unsynthesize_lwe_seeded_ciphertext_vector(
        &mut self,
        entity: LweSeededCiphertextVector,
    ) -> Self::LweSeededCiphertextVectorProto;
    fn destroy_lwe_seeded_ciphertext_vector(&mut self, entity: LweSeededCiphertextVector);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryLweSeededCiphertextVector32, ProtoBinaryLweSeededCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesLweSeededCiphertextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweSeededCiphertextVector32, LweSeededCiphertextVector64};

    impl SynthesizesLweSeededCiphertextVector<Precision32, LweSeededCiphertextVector32> for Maker {
        fn synthesize_lwe_seeded_ciphertext_vector(
            &mut self,
            prototype: &Self::LweSeededCiphertextVectorProto,
        ) -> LweSeededCiphertextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext_vector(
            &mut self,
            entity: LweSeededCiphertextVector32,
        ) -> Self::LweSeededCiphertextVectorProto {
            ProtoBinaryLweSeededCiphertextVector32(entity)
        }

        fn destroy_lwe_seeded_ciphertext_vector(&mut self, _entity: LweSeededCiphertextVector32) {}
    }

    impl SynthesizesLweSeededCiphertextVector<Precision64, LweSeededCiphertextVector64> for Maker {
        fn synthesize_lwe_seeded_ciphertext_vector(
            &mut self,
            prototype: &Self::LweSeededCiphertextVectorProto,
        ) -> LweSeededCiphertextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_seeded_ciphertext_vector(
            &mut self,
            entity: LweSeededCiphertextVector64,
        ) -> Self::LweSeededCiphertextVectorProto {
            ProtoBinaryLweSeededCiphertextVector64(entity)
        }

        fn destroy_lwe_seeded_ciphertext_vector(&mut self, _entity: LweSeededCiphertextVector64) {}
    }
}
