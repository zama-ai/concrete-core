use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use criterion::Criterion;

use paste::paste;

macro_rules! bench {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, FftwEngine, ($($types,)+),
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
            let mut engine = FftwEngine::new(()).unwrap();
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
    (LweCiphertextDiscardingBootstrapFixture1, (FftwFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture2, (FftwFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture1, (FftwFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingBootstrapFixture2, (FftwFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (GlweCiphertextGgswCiphertextExternalProductFixture, (GlweCiphertext, FftwFourierGgswCiphertext, GlweCiphertext)),
    (GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, FftwFourierGgswCiphertext, GlweCiphertext)),
    (GlweCiphertextConversionFixture, (GlweCiphertext, FftwFourierGlweCiphertext)),
    (GlweCiphertextConversionFixture, (FftwFourierGlweCiphertext, GlweCiphertext)),
    (GlweCiphertextsGgswCiphertextFusingCmuxFixture, (GlweCiphertext, GlweCiphertext, FftwFourierGgswCiphertext))
}

#[cfg(feature = "backend_fftw_parallel")]
macro_rules! bench_parallel {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, FftwParallelEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_parallel() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = FftwParallelEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench_parallel!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench_parallel!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_fftw_parallel")]
bench_parallel! {
    (LweCiphertextVectorDiscardingBootstrapFixture1, (FftwFourierLweBootstrapKey,
        FftwGlweCiphertextVector,
        FftwLweCiphertextVector, FftwLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture2, (FftwFourierLweBootstrapKey,
        FftwGlweCiphertextVector,
        FftwLweCiphertextVector, FftwLweCiphertextVector))
}
