use crate::generation::prototyping::PrototypesGlweCiphertext;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweCiphertextEntity;

/// A trait allowing to synthesize an actual GlweCiphertext entity from a prototype.
pub trait SynthesizesGlweCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweCiphertext,
>: PrototypesGlweCiphertext<Precision, KeyDistribution> where
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
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweCiphertext32, GlweCiphertext64};

    impl SynthesizesGlweCiphertext<Precision32, BinaryKeyDistribution, GlweCiphertext32> for Maker {
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

        fn destroy_glwe_ciphertext(&mut self, _entity: GlweCiphertext32) {}
    }

    impl SynthesizesGlweCiphertext<Precision64, BinaryKeyDistribution, GlweCiphertext64> for Maker {
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

        fn destroy_glwe_ciphertext(&mut self, _entity: GlweCiphertext64) {}
    }

    use concrete_core::prelude::{
        GlweCiphertextConsumingRetrievalEngine, GlweCiphertextCreationEngine, GlweCiphertextEntity,
        GlweCiphertextView32, GlweCiphertextView64,
    };

    impl<'a> SynthesizesGlweCiphertext<Precision32, BinaryKeyDistribution, GlweCiphertextView32<'a>>
        for Maker
    {
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

    impl<'a> SynthesizesGlweCiphertext<Precision64, BinaryKeyDistribution, GlweCiphertextView64<'a>>
        for Maker
    {
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

    impl<'a>
        SynthesizesGlweCiphertext<Precision32, BinaryKeyDistribution, GlweCiphertextMutView32<'a>>
        for Maker
    {
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

    impl<'a>
        SynthesizesGlweCiphertext<Precision64, BinaryKeyDistribution, GlweCiphertextMutView64<'a>>
        for Maker
    {
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

#[cfg(feature = "backend_fftw")]
mod backend_fftw {
    use crate::generation::prototypes::{ProtoBinaryGlweCiphertext32, ProtoBinaryGlweCiphertext64};
    use crate::generation::synthesizing::SynthesizesGlweCiphertext;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        FftwFourierGlweCiphertext32, FftwFourierGlweCiphertext64, GlweCiphertextConversionEngine,
    };

    impl SynthesizesGlweCiphertext<Precision32, BinaryKeyDistribution, FftwFourierGlweCiphertext32>
        for Maker
    {
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
            ProtoBinaryGlweCiphertext32(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, _entity: FftwFourierGlweCiphertext32) {}
    }

    impl SynthesizesGlweCiphertext<Precision64, BinaryKeyDistribution, FftwFourierGlweCiphertext64>
        for Maker
    {
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
            ProtoBinaryGlweCiphertext64(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, _entity: FftwFourierGlweCiphertext64) {}
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{ProtoBinaryGlweCiphertext32, ProtoBinaryGlweCiphertext64};
    use crate::generation::synthesizing::SynthesizesGlweCiphertext;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaGlweCiphertext32, CudaGlweCiphertext64, GlweCiphertextConversionEngine,
    };

    impl SynthesizesGlweCiphertext<Precision32, BinaryKeyDistribution, CudaGlweCiphertext32> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> CudaGlweCiphertext32 {
            self.cuda_engine
                .convert_glwe_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: CudaGlweCiphertext32,
        ) -> Self::GlweCiphertextProto {
            let proto = self.cuda_engine.convert_glwe_ciphertext(&entity).unwrap();
            ProtoBinaryGlweCiphertext32(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, _entity: CudaGlweCiphertext32) {}
    }

    impl SynthesizesGlweCiphertext<Precision64, BinaryKeyDistribution, CudaGlweCiphertext64> for Maker {
        fn synthesize_glwe_ciphertext(
            &mut self,
            prototype: &Self::GlweCiphertextProto,
        ) -> CudaGlweCiphertext64 {
            self.cuda_engine
                .convert_glwe_ciphertext(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext(
            &mut self,
            entity: CudaGlweCiphertext64,
        ) -> Self::GlweCiphertextProto {
            let proto = self.cuda_engine.convert_glwe_ciphertext(&entity).unwrap();
            ProtoBinaryGlweCiphertext64(proto)
        }

        fn destroy_glwe_ciphertext(&mut self, _entity: CudaGlweCiphertext64) {}
    }
}
