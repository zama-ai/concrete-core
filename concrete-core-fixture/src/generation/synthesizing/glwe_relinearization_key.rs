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
        DestructionEngine, FftwFourierGlweRelinearizationKey32, FftwFourierGlweRelinearizationKey64,
    };
    use concrete_core::backends::fftw::entities::{FftwFourierGlweRelinearizationKey32, FftwFourierGlweRelinearizationKey64};
    use crate::generation::prototypes::{ProtoFourierRelinearizationKey32, ProtoFourierRelinearizationKey64};

    impl SynthesizesGlweRelinearizationKey<Precision32, FftwFourierGlweRelinearizationKey32> for Maker {
        fn synthesize_glwe_relinearization_key(
            &mut self,
            prototype: &Self::GlweRelinearizationKeyProto,
        ) -> FftwFourierGlweRelinearizationKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_relinearization_key(
            &mut self,
            entity: FftwFourierGlweRelinearizationKey32,
        ) -> Self::GlweRelinearizationKeyProto {
            ProtoFourierRelinearizationKey32(entity)
        }

        fn destroy_glwe_relinearization_key(&mut self, entity: FftwFourierGlweRelinearizationKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweRelinearizationKey<Precision64, FftwFourierGlweRelinearizationKey64> for Maker {
        fn synthesize_glwe_relinearization_key(
            &mut self,
            prototype: &Self::GlweRelinearizationKeyProto,
        ) -> FftwFourierGlweRelinearizationKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_relinearization_key(
            &mut self,
            entity: FftwFourierGlweRelinearizationKey64,
        ) -> Self::GlweRelinearizationKeyProto {
            ProtoFourierRelinearizationKey64(entity)
        }

        fn destroy_glwe_relinearization_key(&mut self, entity: FftwFourierGlweRelinearizationKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}