use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use criterion::Criterion;

use paste::paste;

#[cfg(feature = "backend_fft_parallel")]
macro_rules! bench_parallel {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, ($($key_dist,)*), FftParallelEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_parallel() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = FftParallelEngine::new(()).unwrap();
            $(
                paste!{
                    bench_parallel!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_fft_parallel")]
bench_parallel! {
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweCiphertextVectorDiscardingBootstrapFixture2, (FftFourierLweBootstrapKey,
        GlweCiphertextVector, LweCiphertextVector, LweCiphertextVector))
}
