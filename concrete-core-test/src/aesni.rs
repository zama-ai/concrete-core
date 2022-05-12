use crate::{REPETITIONS, SAMPLE_SIZE};
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use concrete_csprng::seeders::UnixSeeder;
use paste::paste;

macro_rules! test {
    ($fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = AesniEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        AesniEngine,
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
    (GlweCiphertextDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    (GlweCiphertextZeroEncryptionFixture, (GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextVectorZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextVector)),
    (GlweCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    (LweCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    (LweCiphertextZeroEncryptionFixture, (LweSecretKey, LweCiphertext)),
    (LweCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    (LweCiphertextVectorZeroEncryptionFixture, (LweSecretKey, LweCiphertextVector))
}
