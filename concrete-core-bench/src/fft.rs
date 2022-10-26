use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use criterion::Criterion;

use paste::paste;

#[cfg(feature = "backend_fft")]
macro_rules! bench {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision,($($key_dist,)*), FftEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = FftEngine::new(()).unwrap();
            $(
                paste!{
                    bench!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_fft")]
bench! {
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture1, (FftFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture2, (FftFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, FftFourierGgswCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextsGgswCiphertextFusingCmuxFixture, (GlweCiphertext,
        GlweCiphertext, FftFourierGgswCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBitExtractFixture,
        (FftFourierLweBootstrapKey, LweKeyswitchKey, LweCiphertext, LweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingFixture,
        (FftFourierLweBootstrapKey, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
        PlaintextVector, Cleartext, LweCiphertextVectorView, LweCiphertextVectorMutView))
}

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
                    bench_parallel!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench_parallel!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_fft_parallel")]
bench_parallel! {
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweCiphertextVectorDiscardingBootstrapFixture1, (FftFourierLweBootstrapKey,
        GlweCiphertextVector, LweCiphertextVector, LweCiphertextVector))
}
