use crate::{REPETITIONS, SAMPLE_SIZE};
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use paste::paste;

macro_rules! test {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = CudaEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        CudaEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        $(
            paste!{
                test!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+)}
                test!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+)}
            }
        )+
    };
}

test! {
    ((BinaryKeyDistribution), LweCiphertextVectorConversionFixture, (CudaLweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorConversionFixture, (LweCiphertextVectorView,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingConversionFixture,
        (CudaLweCiphertextVector, LweCiphertextVectorMutView)),
    ((BinaryKeyDistribution), LweCiphertextConversionFixture, (CudaLweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingKeyswitchFixture, (CudaLweKeyswitchKey, CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingKeyswitchFixture, (CudaLweKeyswitchKey, CudaLweCiphertext,
        CudaLweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertext,
        CudaLweCiphertext, CudaLweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertext,
        CudaLweCiphertext, CudaLweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution),
        LweCiphertextVectorDiscardingOppositeFixture, (CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    ((BinaryKeyDistribution),
        LweCiphertextVectorDiscardingAdditionFixture, (CudaLweCiphertextVector, CudaLweCiphertextVector))
}

macro_rules! test_amortized {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_amortized_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = AmortizedCudaEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        AmortizedCudaEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        $(
            paste!{
                test_amortized!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+)}
                test_amortized!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+)}
            }
        )+
    };
}

test_amortized! {
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}
