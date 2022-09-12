use crate::{REPETITIONS, SAMPLE_SIZE};
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use concrete_csprng::seeders::UnixSeeder;
use paste::paste;

macro_rules! test {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        DefaultEngine,
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

// Helper aliases for view fixtures which require knowing what the container type is
type Vec32 = Vec<u32>;
type Vec64 = Vec<u64>;
type Slice32 = &'static [u32];
type Slice64 = &'static [u64];
type MutSlice32 = &'static mut [u32];
type MutSlice64 = &'static mut [u64];

test! {
    ((), CleartextCreationFixture, (Cleartext)),
    ((), CleartextRetrievalFixture, (Cleartext)),
    ((), CleartextDiscardingRetrievalFixture, (Cleartext)),
    ((), CleartextArrayCreationFixture, (CleartextArray)),
    ((BinaryKeyDistribution), GlweCiphertextTrivialDecryptionFixture, (PlaintextArray, GlweCiphertext)),
    ((), CleartextArrayDiscardingRetrievalFixture, (CleartextArray)),
    ((), CleartextArrayRetrievalFixture, (CleartextArray)),
    ((BinaryKeyDistribution), GlweCiphertextDecryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingDecryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingEncryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextArray, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextArray, GlweCiphertextMutView)),
    ((BinaryKeyDistribution), GlweCiphertextEncryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextTrivialEncryptionFixture, (PlaintextArray, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextZeroEncryptionFixture, (GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextArrayEncryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayDecryptionFixture, (PlaintextArray, GlweSecretKey, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayTrivialDecryptionFixture, (PlaintextArray, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayTrivialEncryptionFixture, (PlaintextArray, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayDiscardingDecryptionFixture, (PlaintextArray, GlweSecretKey,
        GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayDiscardingEncryptionFixture, (PlaintextArray, GlweSecretKey,
        GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextArrayZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweSeededCiphertextEncryptionFixture, (PlaintextArray, GlweSecretKey, GlweSeededCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextToGlweCiphertextTransformationFixture, (PlaintextArray, GlweSecretKey, GlweSeededCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextArrayEncryptionFixture, (PlaintextArray, GlweSecretKey, GlweSeededCiphertextArray)),
    ((BinaryKeyDistribution), GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationFixture, (PlaintextArray, GlweSecretKey, GlweSeededCiphertextArray, GlweCiphertextArray)),
    ((BinaryKeyDistribution), GlweToLweSecretKeyTransformationFixture, (GlweSecretKey, LweSecretKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyCreationFixture, (Vec, LweBootstrapKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyCreationFixture, (Slice, LweBootstrapKeyView)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyCreationFixture, (MutSlice, LweBootstrapKeyMutView)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyConsumingRetrievalFixture, (LweBootstrapKey, Vec)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyConsumingRetrievalFixture, (LweBootstrapKeyView, Slice)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweBootstrapKeyConsumingRetrievalFixture, (LweBootstrapKeyMutView, MutSlice)),
    ((BinaryKeyDistribution), LweCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextZeroEncryptionFixture, (LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextTrivialEncryptionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextTrivialDecryptionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextArrayZeroEncryptionFixture, (LweSecretKey, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertextView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextArrayDecryptionFixture, (PlaintextArray, LweSecretKey, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayEncryptionFixture, (PlaintextArray, LweSecretKey, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayDiscardingEncryptionFixture, (PlaintextArray, LweSecretKey,
        LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayDiscardingDecryptionFixture, (PlaintextArray, LweSecretKey,
        LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertext, Cleartext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertextView, Cleartext, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextCleartextFusingMultiplicationFixture, (LweCiphertext, Cleartext)),
    ((BinaryKeyDistribution), LweCiphertextFusingOppositeFixture, (LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextFusingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextArrayFusingAdditionFixture, (LweCiphertextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayFusingSubtractionFixture, (LweCiphertextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayDiscardingSubtractionFixture, (LweCiphertextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayDiscardingAdditionFixture, (LweCiphertextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayDiscardingAffineTransformationFixture, (LweCiphertextArray, CleartextArray, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingAdditionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingAdditionFixture, (LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingOppositeFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingOppositeFixture, (LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextFusingAdditionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextArrayTrivialDecryptionFixture, (PlaintextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextArrayTrivialEncryptionFixture, (PlaintextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingDecryptionFixture, (LweCiphertext, LweSecretKey, Plaintext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertextView, Plaintext, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingAdditionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingSubtractionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingSubtractionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingExtractionFixture, (GlweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextArrayGlweCiphertextDiscardingPackingKeyswitchFixture, (LweCiphertextArray, LwePackingKeyswitchKey, GlweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextArrayGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture,
        (LweCiphertextArray, LwePrivateFunctionalPackingKeyswitchKey, GlweCiphertext,
            CleartextArray)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), LweSeededCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweSeededCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextToLweCiphertextTransformationFixture, (Plaintext, LweSecretKey, LweSeededCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextArrayEncryptionFixture, (PlaintextArray, LweSecretKey, LweSeededCiphertextArray)),
    ((BinaryKeyDistribution), LweSeededCiphertextArrayToLweCiphertextArrayTransformationFixture, (PlaintextArray, LweSecretKey, LweSeededCiphertextArray, LweCiphertextArray)),
    ((BinaryKeyDistribution), LweToGlweSecretKeyTransformationFixture, (LweSecretKey, GlweSecretKey)),
    ((), PlaintextCreationFixture, (Plaintext)),
    ((), PlaintextDiscardingRetrievalFixture, (Plaintext)),
    ((), PlaintextRetrievalFixture, (Plaintext)),
    ((), PlaintextArrayDiscardingRetrievalFixture, (PlaintextArray)),
    ((), PlaintextArrayCreationFixture, (PlaintextArray)),
    ((), PlaintextArrayRetrievalFixture, (PlaintextArray))
}
