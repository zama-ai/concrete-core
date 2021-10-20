use crate::generation::prototyping::PrototypesLweKeyswitchKey;
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweKeyswitchKeyEntity;

pub trait SynthesizesLweKeyswitchKey<Precision: IntegerPrecision, LweKeyswitchKey>:
    PrototypesLweKeyswitchKey<
    Precision,
    LweKeyswitchKey::InputKeyDistribution,
    LweKeyswitchKey::OutputKeyDistribution,
>
where
    LweKeyswitchKey: LweKeyswitchKeyEntity,
{
    fn synthesize_lwe_keyswitch_key(
        &mut self,
        prototype: &Self::LweKeyswitchKeyProto,
    ) -> LweKeyswitchKey;
    fn unsynthesize_lwe_keyswitch_key(
        &mut self,
        entity: LweKeyswitchKey,
    ) -> Self::LweKeyswitchKeyProto;
    fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweKeyswitchKey32, ProtoBinaryBinaryLweKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweKeyswitchKey;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{DestructionEngine, LweKeyswitchKey32, LweKeyswitchKey64};

    impl SynthesizesLweKeyswitchKey<Precision32, LweKeyswitchKey32> for Maker {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKey32,
        ) -> Self::LweKeyswitchKeyProto {
            ProtoBinaryBinaryLweKeyswitchKey32(entity)
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKey32) {
            self.default_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesLweKeyswitchKey<Precision64, LweKeyswitchKey64> for Maker {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKey64,
        ) -> Self::LweKeyswitchKeyProto {
            ProtoBinaryBinaryLweKeyswitchKey64(entity)
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKey64) {
            self.default_engine.destroy(entity).unwrap();
        }
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweKeyswitchKey32, ProtoBinaryBinaryLweKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweKeyswitchKey;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweKeyswitchKey32, CudaLweKeyswitchKey64, DestructionEngine,
        LweKeyswitchKeyConversionEngine,
    };

    impl SynthesizesLweKeyswitchKey<Precision32, CudaLweKeyswitchKey32> for Maker {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> CudaLweKeyswitchKey32 {
            self.cuda_engine
                .convert_lwe_keyswitch_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: CudaLweKeyswitchKey32,
        ) -> Self::LweKeyswitchKeyProto {
            let proto = self.cuda_engine.convert_lwe_keyswitch_key(&entity).unwrap();
            self.cuda_engine.destroy(entity).unwrap();
            ProtoBinaryBinaryLweKeyswitchKey32(proto)
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: CudaLweKeyswitchKey32) {
            self.cuda_engine.destroy(entity).unwrap();
        }
    }

    impl SynthesizesLweKeyswitchKey<Precision64, CudaLweKeyswitchKey64> for Maker {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> CudaLweKeyswitchKey64 {
            self.cuda_engine
                .convert_lwe_keyswitch_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: CudaLweKeyswitchKey64,
        ) -> Self::LweKeyswitchKeyProto {
            let proto = self.cuda_engine.convert_lwe_keyswitch_key(&entity).unwrap();
            self.cuda_engine.destroy(entity).unwrap();
            ProtoBinaryBinaryLweKeyswitchKey64(proto)
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: CudaLweKeyswitchKey64) {
            self.cuda_engine.destroy(entity).unwrap();
        }
    }
}
