use crate::generation::prototyping::PrototypesGlweCiphertext;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::GlweCiphertextEntity;

/// A trait allowing to synthesize an actual GlweCiphertext entity from a prototype.
pub trait SynthesizesGlweCiphertext<Precision: IntegerPrecision, GlweCiphertext>:
    PrototypesGlweCiphertext<Precision, GlweCiphertext::KeyDistribution>
where
    GlweCiphertext: GlweCiphertextEntity,
{
    fn synthesize_glwe_ciphertext(
        &mut self,
        prototype: &Self::GlweCiphertextProto,
    ) -> GlweCiphertext;
    fn unsynthesize_glwe_ciphertext(&mut self, entity: GlweCiphertext)
        -> Self::GlweCiphertextProto;
    fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertext);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryGlweCiphertext32, ProtoBinaryGlweCiphertext64};
    use crate::generation::synthesizing::SynthesizesGlweCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, GlweCiphertext32, GlweCiphertext64};

    impl SynthesizesGlweCiphertext<Precision32, GlweCiphertext32> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertext32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertext32,
        ) -> Self::GlweCiphertextProto {
            ProtoBinaryGlweCiphertext32(entity)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertext32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweCiphertext<Precision64, GlweCiphertext64> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertext64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertext64,
        ) -> Self::GlweCiphertextProto {
            ProtoBinaryGlweCiphertext64(entity)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertext64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    use concrete_core::prelude::{
        GlweCiphertextConsumingRetrievalEngine, GlweCiphertextCreationEngine, GlweCiphertextEntity,
        GlweCiphertextView32, GlweCiphertextView64,
    };

    impl<'a> SynthesizesGlweCiphertext<Precision32, GlweCiphertextView32<'a>> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertextView32<'a> {
            let ciphertext = prototype.0.to_owned();
            let polynomial_size = ciphertext.polynomial_size();
            let container = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_glwe_ciphertext(container.leak() as &[u32], polynomial_size)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertextView32,
        ) -> Self::GlweCiphertextProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            let ciphertext = self
                .default_engine
                .create_glwe_ciphertext(
                    unsafe {
                        Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
                    },
                    polynomial_size,
                )
                .unwrap();
            ProtoBinaryGlweCiphertext32(ciphertext)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertextView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesGlweCiphertext<Precision64, GlweCiphertextView64<'a>> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertextView64<'a> {
            let ciphertext = prototype.0.to_owned();
            let polynomial_size = ciphertext.polynomial_size();
            let container = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_glwe_ciphertext(container.leak() as &[u64], polynomial_size)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertextView64,
        ) -> Self::GlweCiphertextProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            let ciphertext = self
                .default_engine
                .create_glwe_ciphertext(
                    unsafe {
                        Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
                    },
                    polynomial_size,
                )
                .unwrap();
            ProtoBinaryGlweCiphertext64(ciphertext)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertextView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len()) };
        }
    }

    use concrete_core::prelude::{GlweCiphertextMutView32, GlweCiphertextMutView64};

    impl<'a> SynthesizesGlweCiphertext<Precision32, GlweCiphertextMutView32<'a>> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertextMutView32<'a> {
            let ciphertext = prototype.0.to_owned();
            let polynomial_size = ciphertext.polynomial_size();
            let container = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_glwe_ciphertext(container.leak(), polynomial_size)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertextMutView32,
        ) -> Self::GlweCiphertextProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            let ciphertext = self
                .default_engine
                .create_glwe_ciphertext(
                    unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) },
                    polynomial_size,
                )
                .unwrap();
            ProtoBinaryGlweCiphertext32(ciphertext)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertextMutView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesGlweCiphertext<Precision64, GlweCiphertextMutView64<'a>> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> GlweCiphertextMutView64<'a> {
            let ciphertext = prototype.0.to_owned();
            let polynomial_size = ciphertext.polynomial_size();
            let container = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_glwe_ciphertext(container.leak(), polynomial_size)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: GlweCiphertextMutView64,
        ) -> Self::GlweCiphertextProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            let ciphertext = self
                .default_engine
                .create_glwe_ciphertext(
                    unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) },
                    polynomial_size,
                )
                .unwrap();
            ProtoBinaryGlweCiphertext64(ciphertext)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: GlweCiphertextMutView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_glwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }
}
#[cfg(feature="backend_fftw")]
mod backend_fftw {
    use crate::generation::prototypes::{ProtoBinaryGlweCiphertext32, ProtoBinaryGlweCiphertext64, ProtoTensorProductGlweCiphertext32, ProtoTensorProductGlweCiphertext64};
    use crate::generation::synthesizing::SynthesizesGlweCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, FftwFourierGlweCiphertext32, FftwFourierGlweCiphertext64, FftwFourierGlweTensorProductCiphertext32, FftwFourierGlweTensorProductCiphertext64, GlweCiphertextConversionEngine};

    impl SynthesizesGlweCiphertext<Precision32, FftwFourierGlweCiphertext32> for 
    Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> FftwFourierGlweCiphertext32 {
            self.fftw_engine
                .convert_glwe_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: FftwFourierGlweCiphertext32,
        ) -> Self::GlweCiphertextProto {
            let proto = self.fftw_engine.convert_glwe_ciphertext(&entity).unwrap();
            self.fftw_engine.destroy(entity).unwrap();
            ProtoBinaryGlweCiphertext32(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: FftwFourierGlweCiphertext32) {
            self.fftw_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesGlweCiphertext<Precision64, FftwFourierGlweCiphertext64> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> FftwFourierGlweCiphertext64 {
            self.fftw_engine
                .convert_glwe_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: FftwFourierGlweCiphertext64,
        ) -> Self::GlweCiphertextProto {
            let proto = self.fftw_engine.convert_glwe_ciphertext(&entity).unwrap();
            self.fftw_engine.destroy(entity).unwrap();
            ProtoBinaryGlweCiphertext64(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: FftwFourierGlweCiphertext64) {
            self.fftw_engine.destroy(entity).unwrap();
        }
    }
    
    impl SynthesizesGlweCiphertext<Precision32, FftwFourierGlweTensorProductCiphertext32> for
    Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            _prototype: &Self::GlweCiphertextProto,
        ) -> FftwFourierGlweTensorProductCiphertext32 {
            unimplemented!()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: FftwFourierGlweTensorProductCiphertext32,
        ) -> Self::GlweCiphertextProto {
            let proto = self.fftw_engine.convert_glwe_ciphertext(&entity).unwrap();
            self.fftw_engine.destroy(entity).unwrap();
            ProtoTensorProductGlweCiphertext32(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, entity: FftwFourierGlweTensorProductCiphertext32) {
            self.fftw_engine.destroy(entity).unwrap();
        }
    }
    
    impl SynthesizesGlweCiphertext<Precision64, FftwFourierGlweTensorProductCiphertext64> for
    Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            _prototype: &Self::GlweCiphertextProto,
        ) -> FftwFourierGlweTensorProductCiphertext64 {
            unimplemented!()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: FftwFourierGlweTensorProductCiphertext64,
        ) -> Self::GlweCiphertextProto {
            ProtoTensorProductGlweCiphertext64(
                self.fftw_engine.convert_glwe_ciphertext(&entity)
                    .unwrap())
        }

        fn destroy_glwe_ciphertext(&mut self, entity: FftwFourierGlweTensorProductCiphertext64) {
            self.fftw_engine.destroy(entity).unwrap();
        }
    }
}

