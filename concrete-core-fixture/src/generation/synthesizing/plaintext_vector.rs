use crate::generation::prototyping::PrototypesPlaintextVector;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::PlaintextVectorEntity;

/// A trait allowing to synthesize an actual plaintext vector entity from a prototype.
pub trait SynthesizesPlaintextVector<Precision: IntegerPrecision, PlaintextVector>:
    PrototypesPlaintextVector<Precision>
where
    PlaintextVector: PlaintextVectorEntity,
{
    fn synthesize_plaintext_vector(
        &mut self,
        prototype: &Self::PlaintextVectorProto,
    ) -> PlaintextVector;
    fn unsynthesize_plaintext_vector(
        &mut self,
        entity: PlaintextVector,
    ) -> Self::PlaintextVectorProto;
    fn destroy_plaintext_vector(&mut self, entity: PlaintextVector);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoPlaintextVector32, ProtoPlaintextVector64};
    use crate::generation::synthesizing::SynthesizesPlaintextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{PlaintextVector32, PlaintextVector64};

    impl SynthesizesPlaintextVector<Precision32, PlaintextVector32> for Maker {
        fn synthesize_plaintext_vector(
            &mut self,
            prototype: &Self::PlaintextVectorProto,
        ) -> PlaintextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_plaintext_vector(
            &mut self,
            entity: PlaintextVector32,
        ) -> Self::PlaintextVectorProto {
            ProtoPlaintextVector32(entity)
        }

        fn destroy_plaintext_vector(&mut self, _entity: PlaintextVector32) {}
    }

    impl SynthesizesPlaintextVector<Precision64, PlaintextVector64> for Maker {
        fn synthesize_plaintext_vector(
            &mut self,
            prototype: &Self::PlaintextVectorProto,
        ) -> PlaintextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_plaintext_vector(
            &mut self,
            entity: PlaintextVector64,
        ) -> Self::PlaintextVectorProto {
            ProtoPlaintextVector64(entity)
        }

        fn destroy_plaintext_vector(&mut self, _entity: PlaintextVector64) {}
    }
}
#[cfg(feature = "backend_cuda")]
mod backend_cuda {
    use crate::generation::prototypes::{ProtoPlaintextVector32, ProtoPlaintextVector64};
    use crate::generation::synthesizing::SynthesizesPlaintextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaPlaintextVector32, CudaPlaintextVector64, PlaintextVectorConversionEngine,
    };

    impl SynthesizesPlaintextVector<Precision32, CudaPlaintextVector32> for Maker {
        fn synthesize_plaintext_vector(
            &mut self,
            prototype: &Self::PlaintextVectorProto,
        ) -> CudaPlaintextVector32 {
            self.cuda_engine
                .convert_plaintext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_plaintext_vector(
            &mut self,
            entity: CudaPlaintextVector32,
        ) -> Self::PlaintextVectorProto {
            let proto = self.cuda_engine.convert_plaintext_vector(&entity).unwrap();
            ProtoPlaintextVector32(proto)
        }
        fn destroy_plaintext_vector(&mut self, _entity: CudaPlaintextVector32) {}
    }

    impl SynthesizesPlaintextVector<Precision64, CudaPlaintextVector64> for Maker {
        fn synthesize_plaintext_vector(
            &mut self,
            prototype: &Self::PlaintextVectorProto,
        ) -> CudaPlaintextVector64 {
            self.cuda_engine
                .convert_plaintext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_plaintext_vector(
            &mut self,
            entity: CudaPlaintextVector64,
        ) -> Self::PlaintextVectorProto {
            let proto = self.cuda_engine.convert_plaintext_vector(&entity).unwrap();
            ProtoPlaintextVector64(proto)
        }
        fn destroy_plaintext_vector(&mut self, _entity: CudaPlaintextVector64) {}
    }
}
