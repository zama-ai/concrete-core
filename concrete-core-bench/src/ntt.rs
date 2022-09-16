use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use criterion::Criterion;

use paste::paste;

macro_rules! bench {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision,($($key_dist,)*), NttEngine, ($($types,)+),
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
            let mut engine = NttEngine::new(()).unwrap();
            $(
                paste!{
                    bench!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

bench! {
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture1, (NttFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture2, (NttFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, NttFourierGgswCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextsGgswCiphertextFusingCmuxFixture, (GlweCiphertext, GlweCiphertext, NttFourierGgswCiphertext))
}
