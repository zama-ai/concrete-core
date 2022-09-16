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
                let mut engine = NttEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        NttEngine,
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
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture1, (NttFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture2, (NttFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture1, (NttFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingBootstrapFixture2, (NttFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), GlweCiphertextGgswCiphertextExternalProductFixture, (GlweCiphertext, NttFourierGgswCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, NttFourierGgswCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextConversionFixture, (GlweCiphertext, NttFourierGlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextConversionFixture, (NttFourierGlweCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextsGgswCiphertextFusingCmuxFixture, (GlweCiphertext, GlweCiphertext,
        NttFourierGgswCiphertext))
}
