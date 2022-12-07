use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use criterion::Criterion;
use paste::paste;

macro_rules! bench {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, ($($key_dist,)*), CudaEngine, ($($types,)+),
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
            let mut engine = CudaEngine::new(()).unwrap();
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
    ((BinaryKeyDistribution), LweCiphertextVectorConversionFixture, (CudaLweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingKeyswitchFixture, (CudaLweKeyswitchKey, CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution),
        LweCiphertextVectorDiscardingOppositeFixture, (CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution),
        LweCiphertextVectorDiscardingAdditionFixture, (CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorCleartextVectorDiscardingMultiplicationFixture,
        (CudaLweCiphertextVector, CudaCleartextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorPlaintextVectorDiscardingAdditionFixture,
        (CudaLweCiphertextVector, CudaPlaintextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBitExtractFixture,
        (CudaFourierLweBootstrapKey, CudaLweKeyswitchKey, CudaLweCiphertext,
            CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture,
        (CudaLweCiphertextVector, CudaLwePrivateFunctionalPackingKeyswitchKey, CudaGlweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingFixture,
        (CudaFourierLweBootstrapKey, CudaLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys,
        CudaPlaintextVector, CudaLweCiphertextVector, CudaLweCiphertextVector))
}

macro_rules! bench_amortized {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, ($($key_dist,)*), AmortizedCudaEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_amortized() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = AmortizedCudaEngine::new(()).unwrap();
            $(
                paste!{
                    bench_amortized!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine,
                    criterion}
                    bench_amortized!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine,
                    criterion}
                }
            )+
        }
    };
}

bench_amortized! {
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}
