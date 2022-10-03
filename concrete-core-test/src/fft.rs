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
                let mut engine = FftEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        FftEngine,
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
