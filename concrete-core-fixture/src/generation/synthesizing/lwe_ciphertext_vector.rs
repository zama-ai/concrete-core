use crate::generation::prototyping::PrototypesLweCiphertextVector;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweCiphertextVectorEntity;

/// A trait allowing to synthesize an actual lwe ciphertext vector entity from a prototype.
pub trait SynthesizesLweCiphertextVector<Precision: IntegerPrecision, LweCiphertextVector>:
    PrototypesLweCiphertextVector<Precision, LweCiphertextVector::KeyDistribution>
where
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
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, LweCiphertextVector32, LweCiphertextVector64};

    impl SynthesizesLweCiphertextVector<Precision32, LweCiphertextVector32> for Maker {
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

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVector32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesLweCiphertextVector<Precision64, LweCiphertextVector64> for Maker {
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

        fn destroy_lwe_ciphertext_vector(&mut self, entity: LweCiphertextVector64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}
#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextVector32, ProtoBinaryLweCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweCiphertextVector32, CudaLweCiphertextVector64, DestructionEngine,
        LweCiphertextVectorConversionEngine,
    };

    impl SynthesizesLweCiphertextVector<Precision32, CudaLweCiphertextVector32> for Maker {
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
            self.cuda_engine.destroy(entity).unwrap();
            ProtoBinaryLweCiphertextVector32(proto)
        }
        fn destroy_lwe_ciphertext_vector(&mut self, entity: CudaLweCiphertextVector32) {
            self.cuda_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesLweCiphertextVector<Precision64, CudaLweCiphertextVector64> for Maker {
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
            self.cuda_engine.destroy(entity).unwrap();
            ProtoBinaryLweCiphertextVector64(proto)
        }
        fn destroy_lwe_ciphertext_vector(&mut self, entity: CudaLweCiphertextVector64) {
            self.cuda_engine.destroy(entity).unwrap();
        }
    }
}
