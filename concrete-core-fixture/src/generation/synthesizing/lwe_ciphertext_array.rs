use crate::generation::prototyping::PrototypesLweCiphertextArray;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweCiphertextArrayEntity;

/// A trait allowing to synthesize an actual lwe ciphertext array entity from a prototype.
pub trait SynthesizesLweCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
    LweCiphertextArray,
>: PrototypesLweCiphertextArray<Precision, KeyDistribution> where
    LweCiphertextArray: LweCiphertextArrayEntity,
{
    fn synthesize_lwe_ciphertext_array(
        &mut self,
        prototype: &Self::LweCiphertextArrayProto,
    ) -> LweCiphertextArray;
    fn unsynthesize_lwe_ciphertext_array(
        &mut self,
        entity: LweCiphertextArray,
    ) -> Self::LweCiphertextArrayProto;
    fn destroy_lwe_ciphertext_array(&mut self, entity: LweCiphertextArray);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextArray32, ProtoBinaryLweCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweCiphertextArray32, LweCiphertextArray64};

    impl SynthesizesLweCiphertextArray<Precision32, BinaryKeyDistribution, LweCiphertextArray32>
        for Maker
    {
        fn synthesize_lwe_ciphertext_array(
            &mut self,
            prototype: &Self::LweCiphertextArrayProto,
        ) -> LweCiphertextArray32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext_array(
            &mut self,
            entity: LweCiphertextArray32,
        ) -> Self::LweCiphertextArrayProto {
            ProtoBinaryLweCiphertextArray32(entity)
        }

        fn destroy_lwe_ciphertext_array(&mut self, _entity: LweCiphertextArray32) {}
    }

    impl SynthesizesLweCiphertextArray<Precision64, BinaryKeyDistribution, LweCiphertextArray64>
        for Maker
    {
        fn synthesize_lwe_ciphertext_array(
            &mut self,
            prototype: &Self::LweCiphertextArrayProto,
        ) -> LweCiphertextArray64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_ciphertext_array(
            &mut self,
            entity: LweCiphertextArray64,
        ) -> Self::LweCiphertextArrayProto {
            ProtoBinaryLweCiphertextArray64(entity)
        }

        fn destroy_lwe_ciphertext_array(&mut self, _entity: LweCiphertextArray64) {}
    }
}
#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextArray32, ProtoBinaryLweCiphertextArray64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextArray;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweCiphertextArray32, CudaLweCiphertextArray64, LweCiphertextArrayConversionEngine,
    };

    impl SynthesizesLweCiphertextArray<Precision32, BinaryKeyDistribution, CudaLweCiphertextArray32>
        for Maker
    {
        fn synthesize_lwe_ciphertext_array(
            &mut self,
            prototype: &Self::LweCiphertextArrayProto,
        ) -> CudaLweCiphertextArray32 {
            self.cuda_engine
                .convert_lwe_ciphertext_array(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext_array(
            &mut self,
            entity: CudaLweCiphertextArray32,
        ) -> Self::LweCiphertextArrayProto {
            let proto = self
                .cuda_engine
                .convert_lwe_ciphertext_array(&entity)
                .unwrap();
            ProtoBinaryLweCiphertextArray32(proto)
        }
        fn destroy_lwe_ciphertext_array(&mut self, _entity: CudaLweCiphertextArray32) {}
    }

    impl SynthesizesLweCiphertextArray<Precision64, BinaryKeyDistribution, CudaLweCiphertextArray64>
        for Maker
    {
        fn synthesize_lwe_ciphertext_array(
            &mut self,
            prototype: &Self::LweCiphertextArrayProto,
        ) -> CudaLweCiphertextArray64 {
            self.cuda_engine
                .convert_lwe_ciphertext_array(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext_array(
            &mut self,
            entity: CudaLweCiphertextArray64,
        ) -> Self::LweCiphertextArrayProto {
            let proto = self
                .cuda_engine
                .convert_lwe_ciphertext_array(&entity)
                .unwrap();
            ProtoBinaryLweCiphertextArray64(proto)
        }
        fn destroy_lwe_ciphertext_array(&mut self, _entity: CudaLweCiphertextArray64) {}
    }
}
