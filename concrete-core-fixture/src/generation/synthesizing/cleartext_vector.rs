use crate::generation::prototyping::PrototypesCleartextVector;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::CleartextVectorEntity;

/// A trait allowing to synthesize an actual cleartext vector entity from a prototype.
pub trait SynthesizesCleartextVector<Precision: IntegerPrecision, CleartextVector>:
    PrototypesCleartextVector<Precision>
where
    CleartextVector: CleartextVectorEntity,
{
    fn synthesize_cleartext_vector(
        &mut self,
        prototype: &Self::CleartextVectorProto,
    ) -> CleartextVector;
    fn unsynthesize_cleartext_vector(
        &mut self,
        entity: CleartextVector,
    ) -> Self::CleartextVectorProto;
    fn destroy_cleartext_vector(&mut self, entity: CleartextVector);
}

mod backend_default {
    use crate::generation::prototypes::{ProtoCleartextVector32, ProtoCleartextVector64};
    use crate::generation::synthesizing::SynthesizesCleartextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{CleartextVector32, CleartextVector64};

    impl SynthesizesCleartextVector<Precision32, CleartextVector32> for Maker {
        fn synthesize_cleartext_vector(
            &mut self,
            prototype: &Self::CleartextVectorProto,
        ) -> CleartextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_cleartext_vector(
            &mut self,
            entity: CleartextVector32,
        ) -> Self::CleartextVectorProto {
            ProtoCleartextVector32(entity)
        }

        fn destroy_cleartext_vector(&mut self, _entity: CleartextVector32) {}
    }

    impl SynthesizesCleartextVector<Precision64, CleartextVector64> for Maker {
        fn synthesize_cleartext_vector(
            &mut self,
            prototype: &Self::CleartextVectorProto,
        ) -> CleartextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_cleartext_vector(
            &mut self,
            entity: CleartextVector64,
        ) -> Self::CleartextVectorProto {
            ProtoCleartextVector64(entity)
        }

        fn destroy_cleartext_vector(&mut self, _entity: CleartextVector64) {}
    }
}
#[cfg(feature = "backend_cuda")]
mod backend_cuda {
    use crate::generation::prototypes::{ProtoCleartextVector32, ProtoCleartextVector64};
    use crate::generation::synthesizing::SynthesizesCleartextVector;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CleartextVectorConversionEngine, CudaCleartextVector32, CudaCleartextVector64,
    };

    impl SynthesizesCleartextVector<Precision32, CudaCleartextVector32> for Maker {
        fn synthesize_cleartext_vector(
            &mut self,
            prototype: &Self::CleartextVectorProto,
        ) -> CudaCleartextVector32 {
            self.cuda_engine
                .convert_cleartext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_cleartext_vector(
            &mut self,
            entity: CudaCleartextVector32,
        ) -> Self::CleartextVectorProto {
            let proto = self.cuda_engine.convert_cleartext_vector(&entity).unwrap();
            ProtoCleartextVector32(proto)
        }
        fn destroy_cleartext_vector(&mut self, _entity: CudaCleartextVector32) {}
    }

    impl SynthesizesCleartextVector<Precision64, CudaCleartextVector64> for Maker {
        fn synthesize_cleartext_vector(
            &mut self,
            prototype: &Self::CleartextVectorProto,
        ) -> CudaCleartextVector64 {
            self.cuda_engine
                .convert_cleartext_vector(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_cleartext_vector(
            &mut self,
            entity: CudaCleartextVector64,
        ) -> Self::CleartextVectorProto {
            let proto = self.cuda_engine.convert_cleartext_vector(&entity).unwrap();
            ProtoCleartextVector64(proto)
        }
        fn destroy_cleartext_vector(&mut self, _entity: CudaCleartextVector64) {}
    }
}
