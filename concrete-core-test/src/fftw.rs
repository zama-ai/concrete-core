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
                let mut engine = FftwEngine::new(()).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        FftwEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
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
    (LweCiphertextDiscardingBootstrapFixture1, (FftwFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture2, (FftwFourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture1, (FftwFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingBootstrapFixture2, (FftwFourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (GlweCiphertextGgswCiphertextExternalProductFixture, (GlweCiphertext, FftwFourierGgswCiphertext, GlweCiphertext)),
    (GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, FftwFourierGgswCiphertext, GlweCiphertext)),
    (GlweCiphertextConversionFixture, (GlweCiphertext, FftwFourierGlweCiphertext)),
    (GlweCiphertextConversionFixture, (FftwFourierGlweCiphertext, GlweCiphertext))
}
