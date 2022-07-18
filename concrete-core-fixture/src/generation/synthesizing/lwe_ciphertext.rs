use crate::generation::prototyping::PrototypesLweCiphertext;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweCiphertextEntity;

/// A trait allowing to synthesize an actual LweCiphertextEntity from a prototype.
pub trait SynthesizesLweCiphertext<Precision: IntegerPrecision, LweCiphertext>:
    PrototypesLweCiphertext<Precision, LweCiphertext::KeyDistribution>
where
    LweCiphertext: LweCiphertextEntity,
{
    fn synthesize_lwe_ciphertext(&mut self, prototype: &Self::LweCiphertextProto) -> LweCiphertext;
    fn unsynthesize_lwe_ciphertext(&mut self, entity: LweCiphertext) -> Self::LweCiphertextProto;
    fn destroy_lwe_ciphertext(&mut self, entity: LweCiphertext);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoBinaryLweCiphertext32, ProtoBinaryLweCiphertext64};
    use crate::generation::synthesizing::SynthesizesLweCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweCiphertext32, LweCiphertext64};

    impl SynthesizesLweCiphertext<Precision32, LweCiphertext32> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertext32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertext32,
        ) -> Self::LweCiphertextProto {
            ProtoBinaryLweCiphertext32(entity)
        }

        fn destroy_lwe_ciphertext(&mut self, _entity: LweCiphertext32) {}
    }

    impl SynthesizesLweCiphertext<Precision64, LweCiphertext64> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertext64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertext64,
        ) -> Self::LweCiphertextProto {
            ProtoBinaryLweCiphertext64(entity)
        }

        fn destroy_lwe_ciphertext(&mut self, _entity: LweCiphertext64) {}
    }

    use concrete_core::prelude::{
        LweCiphertextConsumingRetrievalEngine, LweCiphertextCreationEngine, LweCiphertextView32,
        LweCiphertextView64,
    };

    impl<'a> SynthesizesLweCiphertext<Precision32, LweCiphertextView32<'a>> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertextView32<'a> {
            let ciphertext = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext(container.leak() as &[u32])
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertextView32,
        ) -> Self::LweCiphertextProto {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
            };
            ProtoBinaryLweCiphertext32(
                self.default_engine
                    .create_lwe_ciphertext(reconstructed_vec)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext(&mut self, entity: LweCiphertextView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesLweCiphertext<Precision64, LweCiphertextView64<'a>> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertextView64<'a> {
            let ciphertext = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext(container.leak() as &[u64])
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertextView64,
        ) -> Self::LweCiphertextProto {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
            };
            ProtoBinaryLweCiphertext64(
                self.default_engine
                    .create_lwe_ciphertext(reconstructed_vec)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext(&mut self, entity: LweCiphertextView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    use concrete_core::prelude::{LweCiphertextMutView32, LweCiphertextMutView64};

    impl<'a> SynthesizesLweCiphertext<Precision32, LweCiphertextMutView32<'a>> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertextMutView32<'a> {
            let ciphertext = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext(container.leak())
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertextMutView32,
        ) -> Self::LweCiphertextProto {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
            ProtoBinaryLweCiphertext32(
                self.default_engine
                    .create_lwe_ciphertext(reconstructed_vec)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext(&mut self, entity: LweCiphertextMutView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesLweCiphertext<Precision64, LweCiphertextMutView64<'a>> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> LweCiphertextMutView64<'a> {
            let ciphertext = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(ciphertext)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext(container.leak())
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: LweCiphertextMutView64,
        ) -> Self::LweCiphertextProto {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
            ProtoBinaryLweCiphertext64(
                self.default_engine
                    .create_lwe_ciphertext(reconstructed_vec)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext(&mut self, entity: LweCiphertextMutView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{ProtoBinaryLweCiphertext32, ProtoBinaryLweCiphertext64};
    use crate::generation::synthesizing::SynthesizesLweCiphertext;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweCiphertext32, CudaLweCiphertext64, LweCiphertextConversionEngine,
    };

    impl SynthesizesLweCiphertext<Precision32, CudaLweCiphertext32> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> CudaLweCiphertext32 {
            self.cuda_engine
                .convert_lwe_ciphertext(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: CudaLweCiphertext32,
        ) -> Self::LweCiphertextProto {
            let proto = self.cuda_engine.convert_lwe_ciphertext(&entity).unwrap();
            ProtoBinaryLweCiphertext32(proto)
        }
        fn destroy_lwe_ciphertext(&mut self, _entity: CudaLweCiphertext32) {}
    }

    impl SynthesizesLweCiphertext<Precision64, CudaLweCiphertext64> for Maker {
        fn synthesize_lwe_ciphertext(
            &mut self,
            prototype: &Self::LweCiphertextProto,
        ) -> CudaLweCiphertext64 {
            self.cuda_engine
                .convert_lwe_ciphertext(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext(
            &mut self,
            entity: CudaLweCiphertext64,
        ) -> Self::LweCiphertextProto {
            let proto = self.cuda_engine.convert_lwe_ciphertext(&entity).unwrap();
            ProtoBinaryLweCiphertext64(proto)
        }
        fn destroy_lwe_ciphertext(&mut self, _entity: CudaLweCiphertext64) {}
    }
}
