use crate::generation::prototyping::PrototypesGlweSeededCiphertext;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweSeededCiphertextEntity;

/// A trait allowing to synthesize an actual GlweSeededCiphertextEntity from a prototype.
pub trait SynthesizesGlweSeededCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweSeededCiphertext,
>: PrototypesGlweSeededCiphertext<Precision, KeyDistribution> where
    GlweSeededCiphertext: GlweSeededCiphertextEntity,
{
    fn synthesize_glwe_seeded_ciphertext(
        &mut self,
        prototype: &Self::GlweSeededCiphertextProto,
    ) -> GlweSeededCiphertext;
    fn unsynthesize_glwe_seeded_ciphertext(
        &mut self,
        entity: GlweSeededCiphertext,
    ) -> Self::GlweSeededCiphertextProto;
    fn destroy_glwe_seeded_ciphertext(&mut self, entity: GlweSeededCiphertext);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryGlweSeededCiphertext32, ProtoBinaryGlweSeededCiphertext64,
    };
    use crate::generation::synthesizing::SynthesizesGlweSeededCiphertext;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweSeededCiphertext32, GlweSeededCiphertext64};

    impl SynthesizesGlweSeededCiphertext<Precision32, BinaryKeyDistribution, GlweSeededCiphertext32>
        for Maker
    {
        fn synthesize_glwe_seeded_ciphertext(
            &mut self,
            prototype: &Self::GlweSeededCiphertextProto,
        ) -> GlweSeededCiphertext32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext(
            &mut self,
            entity: GlweSeededCiphertext32,
        ) -> Self::GlweSeededCiphertextProto {
            ProtoBinaryGlweSeededCiphertext32(entity)
        }

        fn destroy_glwe_seeded_ciphertext(&mut self, _entity: GlweSeededCiphertext32) {}
    }

    impl SynthesizesGlweSeededCiphertext<Precision64, BinaryKeyDistribution, GlweSeededCiphertext64>
        for Maker
    {
        fn synthesize_glwe_seeded_ciphertext(
            &mut self,
            prototype: &Self::GlweSeededCiphertextProto,
        ) -> GlweSeededCiphertext64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_seeded_ciphertext(
            &mut self,
            entity: GlweSeededCiphertext64,
        ) -> Self::GlweSeededCiphertextProto {
            ProtoBinaryGlweSeededCiphertext64(entity)
        }

        fn destroy_glwe_seeded_ciphertext(&mut self, _entity: GlweSeededCiphertext64) {}
    }
}
