use crate::generation::prototyping::PrototypesLweCiphertextVector;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweCiphertextVectorEntity;

/// A trait allowing to synthesize an actual lwe ciphertext vector entity from a prototype.
pub trait SynthesizesLweCiphertextVector<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    LweCiphertextVector,
>: PrototypesLweCiphertextVector<Precision, KeyDistribution> where
    LweCiphertextVector: LweCiphertextVectorEntity,
{
    fn synthesize_lwe_ciphertext_vector(
        &mut self,
        prototype: &Self::LweCiphertextVectorProto,
    ) -> LweCiphertextVector;
    fn unsynthesize_lwe_ciphertext_vector(
        &mut self,
        entity: LweCiphertextVector,
    ) -> Self::LweCiphertextVectorProto;
    fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVector);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextVector32, ProtoBinaryLweCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextVector;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorEntity,
    };

    impl SynthesizesLweCiphertextVector<Precision32, BinaryKeyDistribution, LweCiphertextVector32>
        for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVector32,
        ) -> Self::LweCiphertextVectorProto {
            ProtoBinaryLweCiphertextVector32(entity)
        }

        fn destroy_lwe_ciphertext_vector(&mut self, _entity: LweCiphertextVector32) {}
    }

    impl SynthesizesLweCiphertextVector<Precision64, BinaryKeyDistribution, LweCiphertextVector64>
        for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVector64,
        ) -> Self::LweCiphertextVectorProto {
            ProtoBinaryLweCiphertextVector64(entity)
        }

        fn destroy_lwe_ciphertext_vector(&mut self, _entity: LweCiphertextVector64) {}
    }

    use concrete_core::prelude::{
        LweCiphertextVectorConsumingRetrievalEngine, LweCiphertextVectorCreationEngine,
        LweCiphertextVectorView32, LweCiphertextVectorView64,
    };

    impl<'a>
        SynthesizesLweCiphertextVector<
            Precision32,
            BinaryKeyDistribution,
            LweCiphertextVectorView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVectorView32<'a> {
            let ciphertext_vector = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext_vector_from(
                    container.leak() as &[u32],
                    prototype.0.lwe_dimension().to_lwe_size(),
                )
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVectorView32,
        ) -> Self::LweCiphertextVectorProto {
            let lwe_size = entity.lwe_dimension().to_lwe_size();
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
            };
            ProtoBinaryLweCiphertextVector32(
                self.default_engine
                    .create_lwe_ciphertext_vector_from(reconstructed_vec, lwe_size)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVectorView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweCiphertextVector<
            Precision64,
            BinaryKeyDistribution,
            LweCiphertextVectorView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVectorView64<'a> {
            let ciphertext_vector = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext_vector_from(
                    container.leak() as &[u64],
                    prototype.0.lwe_dimension().to_lwe_size(),
                )
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVectorView64,
        ) -> Self::LweCiphertextVectorProto {
            let lwe_size = entity.lwe_dimension().to_lwe_size();
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
            };
            ProtoBinaryLweCiphertextVector64(
                self.default_engine
                    .create_lwe_ciphertext_vector_from(reconstructed_vec, lwe_size)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVectorView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    use concrete_core::prelude::{LweCiphertextVectorMutView32, LweCiphertextVectorMutView64};

    impl<'a>
        SynthesizesLweCiphertextVector<
            Precision32,
            BinaryKeyDistribution,
            LweCiphertextVectorMutView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVectorMutView32<'a> {
            let ciphertext_vector = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext_vector_from(
                    container.leak(),
                    prototype.0.lwe_dimension().to_lwe_size(),
                )
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVectorMutView32,
        ) -> Self::LweCiphertextVectorProto {
            let lwe_size = entity.lwe_dimension().to_lwe_size();
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
            ProtoBinaryLweCiphertextVector32(
                self.default_engine
                    .create_lwe_ciphertext_vector_from(reconstructed_vec, lwe_size)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVectorMutView32) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweCiphertextVector<
            Precision64,
            BinaryKeyDistribution,
            LweCiphertextVectorMutView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> LweCiphertextVectorMutView64<'a> {
            let ciphertext_vector = prototype.0.to_owned();
            let container = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)
                .unwrap();
            self.default_engine
                .create_lwe_ciphertext_vector_from(
                    container.leak(),
                    prototype.0.lwe_dimension().to_lwe_size(),
                )
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: LweCiphertextVectorMutView64,
        ) -> Self::LweCiphertextVectorProto {
            let lwe_size = entity.lwe_dimension().to_lwe_size();
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
            ProtoBinaryLweCiphertextVector64(
                self.default_engine
                    .create_lwe_ciphertext_vector_from(reconstructed_vec, lwe_size)
                    .unwrap(),
            )
        }

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVectorMutView64) {
            // Re-construct the vector so that it frees memory when it's dropped
            let slice = self
                .default_engine
                .consume_retrieve_lwe_ciphertext_vector(entity)
                .unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }
}
#[cfg(feature = "backend_cuda")]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextVector32, ProtoBinaryLweCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextVector;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweCiphertextVector32, CudaLweCiphertextVector64, LweCiphertextVectorConversionEngine,
    };

    impl
        SynthesizesLweCiphertextVector<
            Precision32,
            BinaryKeyDistribution,
            CudaLweCiphertextVector32,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> CudaLweCiphertextVector32 {
            self.cuda_engine
                .convert_lwe_ciphertext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: CudaLweCiphertextVector32,
        ) -> Self::LweCiphertextVectorProto {
            let proto = self
                .cuda_engine
                .convert_lwe_ciphertext_vector(&entity)
                .unwrap();
            ProtoBinaryLweCiphertextVector32(proto)
        }
        fn destroy_lwe_ciphertext_vector(&mut self, _entity: CudaLweCiphertextVector32) {}
    }

    impl
        SynthesizesLweCiphertextVector<
            Precision64,
            BinaryKeyDistribution,
            CudaLweCiphertextVector64,
        > for Maker
    {
        fn synthesize_lwe_ciphertext_vector(
            &mut self,
            prototype: &Self::LweCiphertextVectorProto,
        ) -> CudaLweCiphertextVector64 {
            self.cuda_engine
                .convert_lwe_ciphertext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext_vector(
            &mut self,
            entity: CudaLweCiphertextVector64,
        ) -> Self::LweCiphertextVectorProto {
            let proto = self
                .cuda_engine
                .convert_lwe_ciphertext_vector(&entity)
                .unwrap();
            ProtoBinaryLweCiphertextVector64(proto)
        }
        fn destroy_lwe_ciphertext_vector(&mut self, _entity: CudaLweCiphertextVector64) {}
    }
}
