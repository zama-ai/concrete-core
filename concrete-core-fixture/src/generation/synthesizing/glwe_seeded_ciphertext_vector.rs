use crate::generation::prototyping::PrototypesGlweSeededCiphertextVector;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweSeededCiphertextVectorEntity;

/// A trait allowing to synthesize an actual GlweSeededCiphertextVectorEntity from a prototype.
pub trait SynthesizesGlweSeededCiphertextVector<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweSeededCiphertextVector,
>: PrototypesGlweSeededCiphertextVector<Precision, KeyDistribution> where
    GlweSeededCiphertextVector: GlweSeededCiphertextVectorEntity,
{
    fn synthesize_glwe_seeded_ciphertext_vector(
        &mut self,
        prototype: &Self::GlweSeededCiphertextVectorProto,
    ) -> GlweSeededCiphertextVector;
    fn unsynthesize_glwe_seeded_ciphertext_vector(
        &mut self,
        entity: GlweSeededCiphertextVector,
    ) -> Self::GlweSeededCiphertextVectorProto;
    fn destroy_glwe_seeded_ciphertext_vector(&mut self, entity: GlweSeededCiphertextVector);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryGlweSeededCiphertextVector32, ProtoBinaryGlweSeededCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesGlweSeededCiphertextVector;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweSeededCiphertextVector32, GlweSeededCiphertextVector64};

    impl
        SynthesizesGlweSeededCiphertextVector<
            Precision32,
            BinaryKeyDistribution,
            GlweSeededCiphertextVector32,
        > for Maker
    {
        fn synthesize_glwe_seeded_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweSeededCiphertextVectorProto,
        ) -> GlweSeededCiphertextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext_vector(
            &mut self,
            entity: GlweSeededCiphertextVector32,
        ) -> Self::GlweSeededCiphertextVectorProto {
            ProtoBinaryGlweSeededCiphertextVector32(entity)
        }

        fn destroy_glwe_seeded_ciphertext_vector(&mut self, _entity: GlweSeededCiphertextVector32) {
        }
    }

    impl
        SynthesizesGlweSeededCiphertextVector<
            Precision64,
            BinaryKeyDistribution,
            GlweSeededCiphertextVector64,
        > for Maker
    {
        fn synthesize_glwe_seeded_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweSeededCiphertextVectorProto,
        ) -> GlweSeededCiphertextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext_vector(
            &mut self,
            entity: GlweSeededCiphertextVector64,
        ) -> Self::GlweSeededCiphertextVectorProto {
            ProtoBinaryGlweSeededCiphertextVector64(entity)
        }

        fn destroy_glwe_seeded_ciphertext_vector(&mut self, _entity: GlweSeededCiphertextVector64) {
        }
    }
}
