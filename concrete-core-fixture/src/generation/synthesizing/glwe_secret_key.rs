use crate::generation::prototyping::PrototypesGlweSecretKey;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::GlweSecretKeyEntity;
use concrete_core::prelude::markers::KeyDistributionMarker;

/// A trait allowing to synthesize an actual GLWE secret key entity from a prototype.
pub trait SynthesizesGlweSecretKey<Precision: IntegerPrecision, GlweSecretKey>:
    PrototypesGlweSecretKey<Precision, GlweSecretKey::KeyDistribution>
where
    GlweSecretKey: GlweSecretKeyEntity,
{
    fn synthesize_glwe_secret_key(&mut self, prototype: &Self::GlweSecretKeyProto)
        -> GlweSecretKey;
    fn unsynthesize_glwe_secret_key(&mut self, entity: GlweSecretKey) -> Self::GlweSecretKeyProto;
    fn destroy_glwe_secret_key(&mut self, entity: GlweSecretKey);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryGlweSecretKey32, ProtoBinaryGlweSecretKey64, ProtoTensorProductGlweSecretKey32, ProtoTensorProductGlweSecretKey64};
    use crate::generation::synthesizing::SynthesizesGlweSecretKey;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, GlweSecretKey32, GlweSecretKey64, GlweTensorProductSecretKey32, GlweTensorProductSecretKey64};

    impl SynthesizesGlweSecretKey<Precision32, GlweSecretKey32> for Maker {
        fn synthesize_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweSecretKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_secret_key(
            &mut self,
            entity: GlweSecretKey32,
        ) -> Self::GlweSecretKeyProto {
            ProtoBinaryGlweSecretKey32(entity)
        }

        fn destroy_glwe_secret_key(&mut self, entity: GlweSecretKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweSecretKey<Precision64, GlweSecretKey64> for Maker {
        fn synthesize_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweSecretKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_secret_key(
            &mut self,
            entity: GlweSecretKey64,
        ) -> Self::GlweSecretKeyProto {
            ProtoBinaryGlweSecretKey64(entity)
        }

        fn destroy_glwe_secret_key(&mut self, entity: GlweSecretKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
    impl SynthesizesGlweSecretKey<Precision32, GlweTensorProductSecretKey32> for Maker {
        fn synthesize_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweTensorProductSecretKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_secret_key(
            &mut self,
            entity: GlweTensorProductSecretKey32,
        ) -> Self::GlweSecretKeyProto {
            ProtoTensorProductGlweSecretKey32(entity)
        }

        fn destroy_glwe_secret_key(&mut self, entity: GlweTensorProductSecretKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweSecretKey<Precision64, GlweTensorProductSecretKey64> for Maker {
        fn synthesize_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweTensorProductSecretKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_secret_key(
            &mut self,
            entity: GlweTensorProductSecretKey64,
        ) -> Self::GlweSecretKeyProto {
            ProtoTensorProductGlweSecretKey64(entity)
        }

        fn destroy_glwe_secret_key(&mut self, entity: GlweTensorProductSecretKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}

/// A trait allowing to synthesize an actual tensor product GLWE secret key entity from a prototype.
pub trait SynthesizesTensorProductGlweSecretKey<Precision: IntegerPrecision, 
    InputKeyDistribution: KeyDistributionMarker, GlweSecretKey>:
PrototypesGlweSecretKey<Precision, InputKeyDistribution>
    where
        GlweSecretKey: GlweSecretKeyEntity,
{
    fn synthesize_tensor_product_glwe_secret_key(&mut self, prototype: &Self::GlweSecretKeyProto)
                                  -> GlweSecretKey;
    fn destroy_tensor_product_glwe_secret_key(&mut self, entity: GlweSecretKey);
}

#[cfg(feature="backend_fftw")]
mod backend_fftw {
    use concrete_core::prelude::{DestructionEngine, GlweSecretKeyConversionEngine, GlweSecretKeyTensorProductSameKeyEngine, GlweTensorProductSecretKey32, GlweTensorProductSecretKey64};
    use concrete_core::prelude::markers::BinaryKeyDistribution;
    use crate::generation::{Maker, Precision32, Precision64};
    use crate::generation::synthesizing::SynthesizesTensorProductGlweSecretKey;

    impl SynthesizesTensorProductGlweSecretKey<Precision32, BinaryKeyDistribution, 
        GlweTensorProductSecretKey32> 
    for 
    Maker {
        fn synthesize_tensor_product_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweTensorProductSecretKey32 {
            let fourier_key = self.fftw_engine.create_tensor_product_glwe_secret_key_same_key
            (&prototype.0).unwrap();
            self.fftw_engine.convert_glwe_secret_key(&fourier_key).unwrap()
        }

        fn destroy_tensor_product_glwe_secret_key(&mut self, entity: GlweTensorProductSecretKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesTensorProductGlweSecretKey<Precision64, BinaryKeyDistribution,
        GlweTensorProductSecretKey64>
    for
    Maker {
        fn synthesize_tensor_product_glwe_secret_key(
            &mut self,
            prototype: &Self::GlweSecretKeyProto,
        ) -> GlweTensorProductSecretKey64 {
            let fourier_key = self.fftw_engine.create_tensor_product_glwe_secret_key_same_key
            (&prototype.0).unwrap();
            self.fftw_engine.convert_glwe_secret_key(&fourier_key).unwrap()
        }

        fn destroy_tensor_product_glwe_secret_key(&mut self, entity: GlweTensorProductSecretKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}