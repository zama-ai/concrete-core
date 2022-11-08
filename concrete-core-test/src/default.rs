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
    ((), CleartextVectorCreationFixture, (CleartextVector)),
    ((BinaryKeyDistribution), GlweCiphertextTrivialDecryptionFixture, (PlaintextVector, GlweCiphertext)),
    ((), CleartextVectorDiscardingRetrievalFixture, (CleartextVector)),
    ((), CleartextVectorRetrievalFixture, (CleartextVector)),
    ((BinaryKeyDistribution), GlweCiphertextDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextVector, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextVector, GlweCiphertextMutView)),
    ((BinaryKeyDistribution), GlweCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextTrivialEncryptionFixture, (PlaintextVector, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextZeroEncryptionFixture, (GlweSecretKey, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorTrivialDecryptionFixture, (PlaintextVector, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorTrivialEncryptionFixture, (PlaintextVector, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorDiscardingDecryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweSeededCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextToGlweCiphertextTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector)),
    ((BinaryKeyDistribution), GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector, GlweCiphertextVector)),
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
    ((BinaryKeyDistribution), LweCiphertextVectorZeroEncryptionFixture, (LweSecretKey, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertextView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextVectorDecryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, LweSecretKey,
        LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingDecryptionFixture, (PlaintextVector, LweSecretKey,
        LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertext, Cleartext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertextView, Cleartext, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextCleartextFusingMultiplicationFixture, (LweCiphertext, Cleartext)),
    ((BinaryKeyDistribution), LweCiphertextFusingOppositeFixture, (LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextFusingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextVectorFusingAdditionFixture, (LweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorFusingSubtractionFixture, (LweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingSubtractionFixture, (LweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingAdditionFixture, (LweCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorCleartextVectorDiscardingMultiplicationFixture,
        (LweCiphertextVector, CleartextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorDiscardingAffineTransformationFixture, (LweCiphertextVector, CleartextVector, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingAdditionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingAdditionFixture, (LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingOppositeFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingOppositeFixture, (LweCiphertextView, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextFusingAdditionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextVectorTrivialDecryptionFixture, (PlaintextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextVectorTrivialEncryptionFixture, (PlaintextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingDecryptionFixture, (LweCiphertext, LweSecretKey, Plaintext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextVectorPlaintextVectorDiscardingAdditionFixture,
        (LweCiphertextVector, PlaintextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertextView, Plaintext, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingAdditionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingSubtractionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingSubtractionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingExtractionFixture, (GlweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchFixture, (LweCiphertextVector, LwePackingKeyswitchKey, GlweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture,
        (LweCiphertextVector, LwePrivateFunctionalPackingKeyswitchKey, GlweCiphertext,
            CleartextVector)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyCreationFixture, (Vec, LweKeyswitchKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyCreationFixture, (Slice, LweKeyswitchKeyView)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyCreationFixture, (MutSlice, LweKeyswitchKeyMutView)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyConsumingRetrievalFixture, (LweKeyswitchKey, Vec)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyConsumingRetrievalFixture, (LweKeyswitchKeyView, Slice)),
    ((BinaryKeyDistribution, BinaryKeyDistribution),
        LweKeyswitchKeyConsumingRetrievalFixture, (LweKeyswitchKeyMutView, MutSlice)),
    ((BinaryKeyDistribution), LweSeededCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweSeededCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextToLweCiphertextTransformationFixture, (Plaintext, LweSecretKey, LweSeededCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector)),
    ((BinaryKeyDistribution), LweSeededCiphertextVectorToLweCiphertextVectorTransformationFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution), LweToGlweSecretKeyTransformationFixture, (LweSecretKey, GlweSecretKey)),
    ((), PlaintextCreationFixture, (Plaintext)),
    ((), PlaintextDiscardingRetrievalFixture, (Plaintext)),
    ((), PlaintextRetrievalFixture, (Plaintext)),
    ((), PlaintextVectorDiscardingRetrievalFixture, (PlaintextVector)),
    ((), PlaintextVectorCreationFixture, (PlaintextVector)),
    ((), PlaintextVectorRetrievalFixture, (PlaintextVector))
}

#[cfg(feature = "backend_default_parallel")]
macro_rules! test_parallel {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+)) => {
        paste!{
            #[test]
            fn [< test_parallel_ $fixture:snake _ $precision:snake _ $($types:snake)_+ >]() {
                let mut maker = Maker::default();
                let mut engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
                let test_result =
                    <$fixture as Fixture<
                        $precision,
                        ($($key_dist,)*),
                        DefaultParallelEngine,
                        ($($types,)+),
                    >>::stress_all_parameters(&mut maker, &mut engine, REPETITIONS, SAMPLE_SIZE);
                assert!(test_result);
            }
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        $(
            paste!{
                test_parallel!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+)}
                test_parallel!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+)}
            }
        )+
    };
}

#[cfg(feature = "backend_default_parallel")]
test_parallel! {
    ((BinaryKeyDistribution), LweCiphertextVectorZeroEncryptionFixture, (LweSecretKey, LweCiphertextVector))
}
