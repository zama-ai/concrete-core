use crate::generation::prototyping::PrototypesGlweCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::GlweCiphertextArrayEntity;

/// A trait allowing to synthesize an actual glwe ciphertext array entity from a prototype.
pub trait SynthesizesGlweCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    GlweCiphertextArray,
>: PrototypesGlweCiphertextArray<Precision, KeyDistribution> where
    GlweCiphertextArray: GlweCiphertextArrayEntity,
{
    fn synthesize_glwe_ciphertext_array(
        &mut self,
        prototype: &Self::GlweCiphertextArrayProto,
    ) -> GlweCiphertextArray;
    fn unsynthesize_glwe_ciphertext_array(
        &mut self,
        entity: GlweCiphertextArray,
    ) -> Self::GlweCiphertextArrayProto;
    fn destroy_glwe_ciphertext_array(&mut self, entity: GlweCiphertextArray);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextArray32, ProtoBinaryGlweCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{GlweCiphertextArray32, GlweCiphertextArray64};

    impl SynthesizesGlweCiphertextArray<Precision32, BinaryKeyDistribution, GlweCiphertextArray32>
        for Maker
    {
        fn synthesize_glwe_ciphertext_array(
            &mut self,
            prototype: &Self::GlweCiphertextArrayProto,
        ) -> GlweCiphertextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext_array(
            &mut self,
            entity: GlweCiphertextArray32,
        ) -> Self::GlweCiphertextArrayProto {
            ProtoBinaryGlweCiphertextArray32(entity)
        }

        fn destroy_glwe_ciphertext_array(&mut self, _entity: GlweCiphertextArray32) {}
    }

    impl SynthesizesGlweCiphertextArray<Precision64, BinaryKeyDistribution, GlweCiphertextArray64>
        for Maker
    {
        fn synthesize_glwe_ciphertext_array(
            &mut self,
            prototype: &Self::GlweCiphertextArrayProto,
        ) -> GlweCiphertextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_glwe_ciphertext_array(
            &mut self,
            entity: GlweCiphertextArray64,
        ) -> Self::GlweCiphertextArrayProto {
            ProtoBinaryGlweCiphertextArray64(entity)
        }

        fn destroy_glwe_ciphertext_array(&mut self, _entity: GlweCiphertextArray64) {}
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextArray32, ProtoBinaryGlweCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaGlweCiphertextArray32, CudaGlweCiphertextArray64, GlweCiphertextArrayConversionEngine,
    };

    impl
        SynthesizesGlweCiphertextArray<
            Precision32,
            BinaryKeyDistribution,
            CudaGlweCiphertextArray32,
        > for Maker
    {
        fn synthesize_glwe_ciphertext_array(
            &mut self,
            prototype: &Self::GlweCiphertextArrayProto,
        ) -> CudaGlweCiphertextArray32 {
            self.cuda_engine
                .convert_glwe_ciphertext_array(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_array(
            &mut self,
            entity: CudaGlweCiphertextArray32,
        ) -> Self::GlweCiphertextArrayProto {
            let proto = self
                .cuda_engine
                .convert_glwe_ciphertext_array(&entity)
                .unwrap();
            ProtoBinaryGlweCiphertextArray32(proto)
        }

        fn destroy_glwe_ciphertext_array(&mut self, _entity: CudaGlweCiphertextArray32) {}
    }

    impl
        SynthesizesGlweCiphertextArray<
            Precision64,
            BinaryKeyDistribution,
            CudaGlweCiphertextArray64,
        > for Maker
    {
        fn synthesize_glwe_ciphertext_array(
            &mut self,
            prototype: &Self::GlweCiphertextArrayProto,
        ) -> CudaGlweCiphertextArray64 {
            self.cuda_engine
                .convert_glwe_ciphertext_array(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_array(
            &mut self,
            entity: CudaGlweCiphertextArray64,
        ) -> Self::GlweCiphertextArrayProto {
            let proto = self
                .cuda_engine
                .convert_glwe_ciphertext_array(&entity)
                .unwrap();
            ProtoBinaryGlweCiphertextArray64(proto)
        }

        fn destroy_glwe_ciphertext_array(&mut self, _entity: CudaGlweCiphertextArray64) {}
    }
}
