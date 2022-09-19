use crate::generation::prototyping::PrototypesLweKeyswitchKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweKeyswitchKeyEntity;

pub trait SynthesizesLweKeyswitchKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    LweKeyswitchKey,
>: PrototypesLweKeyswitchKey<Precision, InputKeyDistribution, OutputKeyDistribution> where
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
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweKeyswitchKey32, LweKeyswitchKey64};

    impl
        SynthesizesLweKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKey32,
        > for Maker
    {
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

        fn destroy_lwe_keyswitch_key(&mut self, _entity: LweKeyswitchKey32) {}
    }

    impl
        SynthesizesLweKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKey64,
        > for Maker
    {
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

        fn destroy_lwe_keyswitch_key(&mut self, _entity: LweKeyswitchKey64) {}
    }

    use concrete_core::prelude::{
        LweKeyswitchKeyConsumingRetrievalEngine, LweKeyswitchKeyCreationEngine,
        LweKeyswitchKeyEntity, LweKeyswitchKeyMutView32, LweKeyswitchKeyMutView64,
        LweKeyswitchKeyView32, LweKeyswitchKeyView64,
    };

    impl<'a>
        SynthesizesLweKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKeyMutView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKeyMutView32<'a> {
            let keyswitch_key = prototype.0.to_owned();

            let output_lwe_dimension = keyswitch_key.output_lwe_dimension();
            let decomposition_base_log = keyswitch_key.decomposition_base_log();
            let decomposition_level_count = keyswitch_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(keyswitch_key)
                .unwrap();

            self.default_engine
                .create_lwe_keyswitch_key_from(
                    container.leak() as &mut [u32],
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKeyMutView32,
        ) -> Self::LweKeyswitchKeyProto {
            let output_lwe_dimension = entity.output_lwe_dimension();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };

            ProtoBinaryBinaryLweKeyswitchKey32(
                self.default_engine
                    .create_lwe_keyswitch_key_from(
                        reconstructed_vec,
                        output_lwe_dimension,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKeyMutView32) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKeyMutView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKeyMutView64<'a> {
            let keyswitch_key = prototype.0.to_owned();

            let output_lwe_dimension = keyswitch_key.output_lwe_dimension();
            let decomposition_base_log = keyswitch_key.decomposition_base_log();
            let decomposition_level_count = keyswitch_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(keyswitch_key)
                .unwrap();

            self.default_engine
                .create_lwe_keyswitch_key_from(
                    container.leak() as &mut [u64],
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKeyMutView64,
        ) -> Self::LweKeyswitchKeyProto {
            let output_lwe_dimension = entity.output_lwe_dimension();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };

            ProtoBinaryBinaryLweKeyswitchKey64(
                self.default_engine
                    .create_lwe_keyswitch_key_from(
                        reconstructed_vec,
                        output_lwe_dimension,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKeyMutView64) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKeyView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKeyView32<'a> {
            let keyswitch_key = prototype.0.to_owned();

            let output_lwe_dimension = keyswitch_key.output_lwe_dimension();
            let decomposition_base_log = keyswitch_key.decomposition_base_log();
            let decomposition_level_count = keyswitch_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(keyswitch_key)
                .unwrap();

            self.default_engine
                .create_lwe_keyswitch_key_from(
                    container.leak() as &[u32],
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKeyView32,
        ) -> Self::LweKeyswitchKeyProto {
            let output_lwe_dimension = entity.output_lwe_dimension();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
            };

            ProtoBinaryBinaryLweKeyswitchKey32(
                self.default_engine
                    .create_lwe_keyswitch_key_from(
                        reconstructed_vec,
                        output_lwe_dimension,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKeyView32) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweKeyswitchKeyView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_keyswitch_key(
            &mut self,
            prototype: &Self::LweKeyswitchKeyProto,
        ) -> LweKeyswitchKeyView64<'a> {
            let keyswitch_key = prototype.0.to_owned();

            let output_lwe_dimension = keyswitch_key.output_lwe_dimension();
            let decomposition_base_log = keyswitch_key.decomposition_base_log();
            let decomposition_level_count = keyswitch_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(keyswitch_key)
                .unwrap();

            self.default_engine
                .create_lwe_keyswitch_key_from(
                    container.leak() as &[u64],
                    output_lwe_dimension,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_keyswitch_key(
            &mut self,
            entity: LweKeyswitchKeyView64,
        ) -> Self::LweKeyswitchKeyProto {
            let output_lwe_dimension = entity.output_lwe_dimension();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
            };

            ProtoBinaryBinaryLweKeyswitchKey64(
                self.default_engine
                    .create_lwe_keyswitch_key_from(
                        reconstructed_vec,
                        output_lwe_dimension,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_keyswitch_key(&mut self, entity: LweKeyswitchKeyView64) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_keyswitch_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len()) };
        }
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweKeyswitchKey32, ProtoBinaryBinaryLweKeyswitchKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweKeyswitchKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaLweKeyswitchKey32, CudaLweKeyswitchKey64, LweKeyswitchKeyConversionEngine,
    };

    impl
        SynthesizesLweKeyswitchKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            CudaLweKeyswitchKey32,
        > for Maker
    {
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
            ProtoBinaryBinaryLweKeyswitchKey32(proto)
        }

        fn destroy_lwe_keyswitch_key(&mut self, _entity: CudaLweKeyswitchKey32) {}
    }

    impl
        SynthesizesLweKeyswitchKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            CudaLweKeyswitchKey64,
        > for Maker
    {
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
            ProtoBinaryBinaryLweKeyswitchKey64(proto)
        }

        fn destroy_lwe_keyswitch_key(&mut self, _entity: CudaLweKeyswitchKey64) {}
    }
}
