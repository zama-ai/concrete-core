use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use criterion::Criterion;
use paste::paste;

macro_rules! bench {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, CudaEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = CudaEngine::new(()).unwrap();
            $(
                paste!{
                    bench!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

bench! {
    (LweCiphertextVectorConversionFixture, (CudaLweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextVectorDiscardingKeyswitchFixture, (CudaLweKeyswitchKey, CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}

macro_rules! bench_amortized {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, AmortizedCudaEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_amortized() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = AmortizedCudaEngine::new(()).unwrap();
            $(
                paste!{
                    bench_amortized!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine,
                    criterion}
                    bench_amortized!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine,
                    criterion}
                }
            )+
        }
    };
}

bench_amortized! {
    (LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}
