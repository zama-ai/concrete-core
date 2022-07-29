use crate::generation::prototyping::PrototypesLweBootstrapKey;
use crate::generation::{IntegerPrecision, KeyDistributionMarker};
use concrete_core::prelude::LweBootstrapKeyEntity;

/// A trait allowing to synthesize an actual lwe bootstrap key entity from a prototype.
pub trait SynthesizesLweBootstrapKey<
    Precision: IntegerPrecision,
    InputKeyDistribution: KeyDistributionMarker,
    OutputKeyDistribution: KeyDistributionMarker,
    LweBootstrapKey,
>: PrototypesLweBootstrapKey<Precision, InputKeyDistribution, OutputKeyDistribution> where
    LweBootstrapKey: LweBootstrapKeyEntity,
{
    fn synthesize_lwe_bootstrap_key(
        &mut self,
        prototype: &Self::LweBootstrapKeyProto,
    ) -> LweBootstrapKey;
    fn unsynthesize_lwe_bootstrap_key(
        &mut self,
        entity: LweBootstrapKey,
    ) -> Self::LweBootstrapKeyProto;
    fn destroy_lwe_bootstrap_key(&mut self, entity: LweBootstrapKey);
}

mod backend_default {
    use crate::generation::prototypes::{
        ProtoBinaryBinaryLweBootstrapKey32, ProtoBinaryBinaryLweBootstrapKey64,
    };
    use crate::generation::synthesizing::SynthesizesLweBootstrapKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{LweBootstrapKey32, LweBootstrapKey64};

    impl
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKey32,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKey32 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKey32,
        ) -> Self::LweBootstrapKeyProto {
            ProtoBinaryBinaryLweBootstrapKey32(entity)
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: LweBootstrapKey32) {}
    }

    impl
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKey64,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKey64 {
            prototype.0.to_owned()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKey64,
        ) -> Self::LweBootstrapKeyProto {
            ProtoBinaryBinaryLweBootstrapKey64(entity)
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: LweBootstrapKey64) {}
    }

    use concrete_core::prelude::{
        LweBootstrapKeyConstructionEngine, LweBootstrapKeyConsumingRetrievalEngine,
        LweBootstrapKeyEntity, LweBootstrapKeyMutView32, LweBootstrapKeyMutView64,
        LweBootstrapKeyView32, LweBootstrapKeyView64,
    };

    impl<'a>
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKeyMutView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKeyMutView32<'a> {
            let bootstrap_key = prototype.0.to_owned();

            let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();
            let poly_size = bootstrap_key.polynomial_size();
            let decomposition_base_log = bootstrap_key.decomposition_base_log();
            let decomposition_level_count = bootstrap_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(bootstrap_key)
                .unwrap();

            self.default_engine
                .construct_lwe_bootstrap_key(
                    container.leak() as &mut [u32],
                    glwe_size,
                    poly_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKeyMutView32,
        ) -> Self::LweBootstrapKeyProto {
            let glwe_size = entity.glwe_dimension().to_glwe_size();
            let poly_size = entity.polynomial_size();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };

            ProtoBinaryBinaryLweBootstrapKey32(
                self.default_engine
                    .construct_lwe_bootstrap_key(
                        reconstructed_vec,
                        glwe_size,
                        poly_size,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_bootstrap_key(&mut self, entity: LweBootstrapKeyMutView32) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKeyMutView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKeyMutView64<'a> {
            let bootstrap_key = prototype.0.to_owned();

            let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();
            let poly_size = bootstrap_key.polynomial_size();
            let decomposition_base_log = bootstrap_key.decomposition_base_log();
            let decomposition_level_count = bootstrap_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(bootstrap_key)
                .unwrap();

            self.default_engine
                .construct_lwe_bootstrap_key(
                    container.leak() as &mut [u64],
                    glwe_size,
                    poly_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKeyMutView64,
        ) -> Self::LweBootstrapKeyProto {
            let glwe_size = entity.glwe_dimension().to_glwe_size();
            let poly_size = entity.polynomial_size();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();
            let reconstructed_vec =
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };

            ProtoBinaryBinaryLweBootstrapKey64(
                self.default_engine
                    .construct_lwe_bootstrap_key(
                        reconstructed_vec,
                        glwe_size,
                        poly_size,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_bootstrap_key(&mut self, entity: LweBootstrapKeyMutView64) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKeyView32<'a>,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKeyView32<'a> {
            let bootstrap_key = prototype.0.to_owned();

            let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();
            let poly_size = bootstrap_key.polynomial_size();
            let decomposition_base_log = bootstrap_key.decomposition_base_log();
            let decomposition_level_count = bootstrap_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(bootstrap_key)
                .unwrap();

            self.default_engine
                .construct_lwe_bootstrap_key(
                    container.leak() as &[u32],
                    glwe_size,
                    poly_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKeyView32,
        ) -> Self::LweBootstrapKeyProto {
            let glwe_size = entity.glwe_dimension().to_glwe_size();
            let poly_size = entity.polynomial_size();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
            };

            ProtoBinaryBinaryLweBootstrapKey32(
                self.default_engine
                    .construct_lwe_bootstrap_key(
                        reconstructed_vec,
                        glwe_size,
                        poly_size,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_bootstrap_key(&mut self, entity: LweBootstrapKeyView32) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len()) };
        }
    }

    impl<'a>
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            LweBootstrapKeyView64<'a>,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> LweBootstrapKeyView64<'a> {
            let bootstrap_key = prototype.0.to_owned();

            let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();
            let poly_size = bootstrap_key.polynomial_size();
            let decomposition_base_log = bootstrap_key.decomposition_base_log();
            let decomposition_level_count = bootstrap_key.decomposition_level_count();

            let container = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(bootstrap_key)
                .unwrap();

            self.default_engine
                .construct_lwe_bootstrap_key(
                    container.leak() as &[u64],
                    glwe_size,
                    poly_size,
                    decomposition_base_log,
                    decomposition_level_count,
                )
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            entity: LweBootstrapKeyView64,
        ) -> Self::LweBootstrapKeyProto {
            let glwe_size = entity.glwe_dimension().to_glwe_size();
            let poly_size = entity.polynomial_size();
            let decomposition_base_log = entity.decomposition_base_log();
            let decomposition_level_count = entity.decomposition_level_count();

            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();
            let reconstructed_vec = unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
            };

            ProtoBinaryBinaryLweBootstrapKey64(
                self.default_engine
                    .construct_lwe_bootstrap_key(
                        reconstructed_vec,
                        glwe_size,
                        poly_size,
                        decomposition_base_log,
                        decomposition_level_count,
                    )
                    .unwrap(),
            )
        }

        fn destroy_lwe_bootstrap_key(&mut self, entity: LweBootstrapKeyView64) {
            let slice = self
                .default_engine
                .consume_retrieve_lwe_bootstrap_key(entity)
                .unwrap();

            unsafe { Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len()) };
        }
    }
}

#[cfg(feature = "backend_fftw")]
mod backend_fftw {
    use crate::generation::synthesizing::SynthesizesLweBootstrapKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        FftwFourierLweBootstrapKey32, FftwFourierLweBootstrapKey64, LweBootstrapKeyConversionEngine,
    };

    impl
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            FftwFourierLweBootstrapKey32,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> FftwFourierLweBootstrapKey32 {
            self.fftw_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: FftwFourierLweBootstrapKey32,
        ) -> Self::LweBootstrapKeyProto {
            todo!()
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: FftwFourierLweBootstrapKey32) {}
    }

    impl
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            FftwFourierLweBootstrapKey64,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> FftwFourierLweBootstrapKey64 {
            self.fftw_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: FftwFourierLweBootstrapKey64,
        ) -> Self::LweBootstrapKeyProto {
            todo!()
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: FftwFourierLweBootstrapKey64) {}
    }
}

#[cfg(feature = "backend_fft")]
mod backend_fft {
    use crate::generation::synthesizing::SynthesizesLweBootstrapKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64, LweBootstrapKeyConversionEngine,
    };

    impl
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            FftFourierLweBootstrapKey32,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> FftFourierLweBootstrapKey32 {
            self.fft_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: FftFourierLweBootstrapKey32,
        ) -> Self::LweBootstrapKeyProto {
            todo!()
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: FftFourierLweBootstrapKey32) {}
    }

    impl
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            FftFourierLweBootstrapKey64,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> FftFourierLweBootstrapKey64 {
            self.fft_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: FftFourierLweBootstrapKey64,
        ) -> Self::LweBootstrapKeyProto {
            todo!()
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: FftFourierLweBootstrapKey64) {}
    }
}

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
mod backend_cuda {
    use crate::generation::synthesizing::SynthesizesLweBootstrapKey;
    use crate::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, LweBootstrapKeyConversionEngine,
    };

    impl
        SynthesizesLweBootstrapKey<
            Precision32,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            CudaFourierLweBootstrapKey32,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> CudaFourierLweBootstrapKey32 {
            self.cuda_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: CudaFourierLweBootstrapKey32,
        ) -> Self::LweBootstrapKeyProto {
            unimplemented!(
                "The conversion of the Fourier bootstrap key from GPU to CPU is not \
            implemented"
            );
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: CudaFourierLweBootstrapKey32) {}
    }

    impl
        SynthesizesLweBootstrapKey<
            Precision64,
            BinaryKeyDistribution,
            BinaryKeyDistribution,
            CudaFourierLweBootstrapKey64,
        > for Maker
    {
        fn synthesize_lwe_bootstrap_key(
            &mut self,
            prototype: &Self::LweBootstrapKeyProto,
        ) -> CudaFourierLweBootstrapKey64 {
            self.cuda_engine
                .convert_lwe_bootstrap_key(&prototype.0)
                .unwrap()
        }

        fn unsynthesize_lwe_bootstrap_key(
            &mut self,
            _entity: CudaFourierLweBootstrapKey64,
        ) -> Self::LweBootstrapKeyProto {
            unimplemented!(
                "The conversion of the Fourier bootstrap key from GPU to CPU is not \
            implemented"
            );
        }

        fn destroy_lwe_bootstrap_key(&mut self, _entity: CudaFourierLweBootstrapKey64) {}
    }
}
