use crate::generation::prototyping::PrototypesGlweRelinearizationKey;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::GlweRelinearizationKeyEntity;

/// A trait allowing to synthesize an actual GLWE relinearization key entity from a prototype.
pub trait SynthesizesGlweRelinearizationKey<Precision: IntegerPrecision, GlweRelinearizationKey>:
PrototypesGlweRelinearizationKey<
    Precision,
    GlweRelinearizationKey::KeyDistribution,
>
    where
        GlweRelinearizationKey: GlweRelinearizationKeyEntity,
{
    fn synthesize_glwe_relinearization_key(
        &mut self,
        prototype: &Self::GlweRelinearizationKeyProto,
    ) -> GlweRelinearizationKey;
    fn unsynthesize_glwe_relinearization_key(
        &mut self,
        entity: GlweRelinearizationKey,
    ) -> Self::GlweRelinearizationKeyProto;
    fn destroy_glwe_relinearization_key(&mut self, entity: GlweRelinearizationKey);
}

mod backend_fftw {
    use crate::generation::synthesizing::{SynthesizesGlweRelinearizationKey};
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        DestructionEngine, FftwStandardGlweRelinearizationKey32, FftwStandardGlweRelinearizationKey64,
    };
    use crate::generation::prototypes::{ProtoStandardRelinearizationKey32, ProtoStandardRelinearizationKey64};

    impl SynthesizesGlweRelinearizationKey<Precision32, FftwStandardGlweRelinearizationKey32> for Maker {
        fn synthesize_glwe_relinearization_key(
            &mut self,
            prototype: &Self::GlweRelinearizationKeyProto,
        ) -> FftwStandardGlweRelinearizationKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_relinearization_key(
            &mut self,
            entity: FftwStandardGlweRelinearizationKey32,
        ) -> Self::GlweRelinearizationKeyProto {
            ProtoStandardRelinearizationKey32(entity)
        }

        fn destroy_glwe_relinearization_key(&mut self, entity: FftwStandardGlweRelinearizationKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweRelinearizationKey<Precision64, FftwStandardGlweRelinearizationKey64> for Maker {
        fn synthesize_glwe_relinearization_key(
            &mut self,
            prototype: &Self::GlweRelinearizationKeyProto,
        ) -> FftwStandardGlweRelinearizationKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_relinearization_key(
            &mut self,
            entity: FftwStandardGlweRelinearizationKey64,
        ) -> Self::GlweRelinearizationKeyProto {
            ProtoStandardRelinearizationKey64(entity)
        }

        fn destroy_glwe_relinearization_key(&mut self, entity: FftwStandardGlweRelinearizationKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}