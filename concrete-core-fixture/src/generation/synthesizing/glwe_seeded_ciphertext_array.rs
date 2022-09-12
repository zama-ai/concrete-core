use crate::generation::prototyping::PrototypesGlweSeededCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweSeededCiphertextArrayEntity;

/// A trait allowing to synthesize an actual GlweSeededCiphertextArrayEntity from a prototype.
pub trait SynthesizesGlweSeededCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweSeededCiphertextArray,
>: PrototypesGlweSeededCiphertextArray<Precision, KeyDistribution> where
    GlweSeededCiphertextArray: GlweSeededCiphertextArrayEntity,
{
    fn synthesize_glwe_seeded_ciphertext_array(
        &mut self,
        prototype: &Self::GlweSeededCiphertextArrayProto,
    ) -> GlweSeededCiphertextArray;
    fn unsynthesize_glwe_seeded_ciphertext_array(
        &mut self,
        entity: GlweSeededCiphertextArray,
    ) -> Self::GlweSeededCiphertextArrayProto;
    fn destroy_glwe_seeded_ciphertext_array(&mut self, entity: GlweSeededCiphertextArray);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryGlweSeededCiphertextArray32, ProtoBinaryGlweSeededCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesGlweSeededCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweSeededCiphertextArray32, GlweSeededCiphertextArray64};

    impl
        SynthesizesGlweSeededCiphertextArray<
            Precision32,
            BinaryKeyDistribution,
            GlweSeededCiphertextArray32,
        > for Maker
    {
        fn synthesize_glwe_seeded_ciphertext_array(
            &mut self,
            prototype: &Self::GlweSeededCiphertextArrayProto,
        ) -> GlweSeededCiphertextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext_array(
            &mut self,
            entity: GlweSeededCiphertextArray32,
        ) -> Self::GlweSeededCiphertextArrayProto {
            ProtoBinaryGlweSeededCiphertextArray32(entity)
        }

        fn destroy_glwe_seeded_ciphertext_array(&mut self, _entity: GlweSeededCiphertextArray32) {}
    }

    impl
        SynthesizesGlweSeededCiphertextArray<
            Precision64,
            BinaryKeyDistribution,
            GlweSeededCiphertextArray64,
        > for Maker
    {
        fn synthesize_glwe_seeded_ciphertext_array(
            &mut self,
            prototype: &Self::GlweSeededCiphertextArrayProto,
        ) -> GlweSeededCiphertextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext_array(
            &mut self,
            entity: GlweSeededCiphertextArray64,
        ) -> Self::GlweSeededCiphertextArrayProto {
            ProtoBinaryGlweSeededCiphertextArray64(entity)
        }

        fn destroy_glwe_seeded_ciphertext_array(&mut self, _entity: GlweSeededCiphertextArray64) {}
    }
}
