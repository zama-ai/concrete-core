use crate::{REPETITIONS, SAMPLE_SIZE};
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use paste::paste;

macro_rules! test {
    ($fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = CudaEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        CudaEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
    };
    ($(($fixture: ident, $precision: ident, ($($types:ident),+))),+) => {
        $(
            test!{$fixture, $precision, ($($types),+)}
        )+
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        $(
            paste!{
                test!{$fixture, Precision32, ($([< $types 32 >]),+)}
                test!{$fixture, Precision64, ($([< $types 64 >]),+)}
            }
        )+
    };
}

test! {
    (LweCiphertextVectorConversionFixture, (CudaLweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextConversionFixture, (CudaLweCiphertext, LweCiphertext)),
    (LweCiphertextVectorDiscardingKeyswitchFixture, (CudaLweKeyswitchKey, CudaLweCiphertextVector,
        CudaLweCiphertextVector)),
    (LweCiphertextDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertext,
        CudaLweCiphertext, CudaLweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertext,
        CudaLweCiphertext, CudaLweCiphertext)),
    (LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}

macro_rules! test_amortized {
    ($fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_amortized_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = AmortizedCudaEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        AmortizedCudaEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
    };
    ($(($fixture: ident, $precision: ident, ($($types:ident),+))),+) => {
        $(
            test_amortized!{$fixture, $precision, ($($types),+)}
        )+
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        $(
            paste!{
                test_amortized!{$fixture, Precision32, ($([< $types 32 >]),+)}
                test_amortized!{$fixture, Precision64, ($([< $types 64 >]),+)}
            }
        )+
    };
}

test_amortized! {
    (LweCiphertextVectorDiscardingBootstrapFixture1, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector)),
    (LweCiphertextVectorDiscardingBootstrapFixture2, (CudaFourierLweBootstrapKey,
        CudaGlweCiphertextVector,
        CudaLweCiphertextVector, CudaLweCiphertextVector))
}
