use crate::generation::prototyping::PrototypesGlweCiphertextVector;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweCiphertextVectorEntity;

/// A trait allowing to synthesize an actual glwe ciphertext vector entity from a prototype.
pub trait SynthesizesGlweCiphertextVector<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweCiphertextVector,
>: PrototypesGlweCiphertextVector<Precision, KeyDistribution> where
    GlweCiphertextVector: GlweCiphertextVectorEntity,
{
    fn synthesize_glwe_ciphertext_vector(
        &mut self,
        prototype: &Self::GlweCiphertextVectorProto,
    ) -> GlweCiphertextVector;
    fn unsynthesize_glwe_ciphertext_vector(
        &mut self,
        entity: GlweCiphertextVector,
    ) -> Self::GlweCiphertextVectorProto;
    fn destroy_glwe_ciphertext_vector(&mut self, entity: GlweCiphertextVector);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextVector32, ProtoBinaryGlweCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextVector;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweCiphertextVector32, GlweCiphertextVector64};

    impl SynthesizesGlweCiphertextVector<Precision32, BinaryKeyDistribution, GlweCiphertextVector32>
        for Maker
    {
        fn synthesize_glwe_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweCiphertextVectorProto,
        ) -> GlweCiphertextVector32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext_vector(
            &mut self,
            entity: GlweCiphertextVector32,
        ) -> Self::GlweCiphertextVectorProto {
            ProtoBinaryGlweCiphertextVector32(entity)
        }

        fn destroy_glwe_ciphertext_vector(&mut self, _entity: GlweCiphertextVector32) {}
    }

    impl SynthesizesGlweCiphertextVector<Precision64, BinaryKeyDistribution, GlweCiphertextVector64>
        for Maker
    {
        fn synthesize_glwe_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweCiphertextVectorProto,
        ) -> GlweCiphertextVector64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext_vector(
            &mut self,
            entity: GlweCiphertextVector64,
        ) -> Self::GlweCiphertextVectorProto {
            ProtoBinaryGlweCiphertextVector64(entity)
        }

        fn destroy_glwe_ciphertext_vector(&mut self, _entity: GlweCiphertextVector64) {}
    }
}

#[cfg(feature = "backend_cuda")]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextVector32, ProtoBinaryGlweCiphertextVector64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextVector;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaGlweCiphertextVector32, CudaGlweCiphertextVector64,
        GlweCiphertextVectorConversionEngine,
    };

    impl
        SynthesizesGlweCiphertextVector<
            Precision32,
            BinaryKeyDistribution,
            CudaGlweCiphertextVector32,
        > for Maker
    {
        fn synthesize_glwe_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweCiphertextVectorProto,
        ) -> CudaGlweCiphertextVector32 {
            self.cuda_engine
                .convert_glwe_ciphertext_vector(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_vector(
            &mut self,
            entity: CudaGlweCiphertextVector32,
        ) -> Self::GlweCiphertextVectorProto {
            let proto = self
                .cuda_engine
                .convert_glwe_ciphertext_vector(&entity)
                .unwrap();
            ProtoBinaryGlweCiphertextVector32(proto)
        }

        fn destroy_glwe_ciphertext_vector(&mut self, _entity: CudaGlweCiphertextVector32) {}
    }

    impl
        SynthesizesGlweCiphertextVector<
            Precision64,
            BinaryKeyDistribution,
            CudaGlweCiphertextVector64,
        > for Maker
    {
        fn synthesize_glwe_ciphertext_vector(
            &mut self,
            prototype: &Self::GlweCiphertextVectorProto,
        ) -> CudaGlweCiphertextVector64 {
            self.cuda_engine
                .convert_glwe_ciphertext_vector(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_vector(
            &mut self,
            entity: CudaGlweCiphertextVector64,
        ) -> Self::GlweCiphertextVectorProto {
            let proto = self
                .cuda_engine
                .convert_glwe_ciphertext_vector(&entity)
                .unwrap();
            ProtoBinaryGlweCiphertextVector64(proto)
        }

        fn destroy_glwe_ciphertext_vector(&mut self, _entity: CudaGlweCiphertextVector64) {}
    }
}
