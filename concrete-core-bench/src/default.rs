use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{BinaryKeyDistribution, Maker, Precision32, Precision64};
use concrete_csprng::seeders::UnixSeeder;
use criterion::Criterion;

use paste::paste;

macro_rules! bench {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, ($($key_dist,)*), DefaultEngine, ($($types,)+),
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
            let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

// Helper aliases for view fixtures which require knowing what the container type is
type Vec32 = Vec<u32>;
type Vec64 = Vec<u64>;
type Slice32 = &'static [u32];
type Slice64 = &'static [u64];
type MutSlice32 = &'static mut [u32];
type MutSlice64 = &'static mut [u64];

bench! {
    ((),CleartextCreationFixture, (Cleartext)),
    ((),CleartextRetrievalFixture, (Cleartext)),
    ((),CleartextDiscardingRetrievalFixture, (Cleartext)),
    ((),CleartextVectorCreationFixture, (CleartextVector)),
    ((BinaryKeyDistribution),GlweCiphertextTrivialDecryptionFixture, (PlaintextVector, GlweCiphertext)),
    ((),CleartextVectorDiscardingRetrievalFixture, (CleartextVector)),
    ((),CleartextVectorRetrievalFixture, (CleartextVector)),
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
    ((BinaryKeyDistribution),GlweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextVectorZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextCreationFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertext, Vec)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextView, Slice)),
    ((BinaryKeyDistribution), GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), GlweSecretKeyGenerationFixture, (GlweSecretKey)),
    ((BinaryKeyDistribution), GlweSeededCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextToGlweCiphertextTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext, GlweCiphertext)),
    ((BinaryKeyDistribution), GlweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector)),
    ((BinaryKeyDistribution), GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector, GlweCiphertextVector)),
    ((BinaryKeyDistribution), GlweToLweSecretKeyTransformationFixture, (GlweSecretKey, LweSecretKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweBootstrapKeyGenerationFixture, (LweSecretKey, GlweSecretKey, LweBootstrapKey)),
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
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertextView, Plaintext, LweCiphertextMutView)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingAdditionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextDiscardingSubtractionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextPlaintextFusingSubtractionFixture, (Plaintext, LweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextDiscardingExtractionFixture, (GlweCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchFixture, (LweCiphertextVector,
        LwePackingKeyswitchKey, GlweCiphertext)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextCreationFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertext, Vec)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextView, Slice)),
    ((BinaryKeyDistribution), LweCiphertextConsumingRetrievalFixture, (LweCiphertextMutView, MutSlice)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweKeyswitchKeyGenerationFixture, (LweSecretKey, LweSecretKey, LweKeyswitchKey)),
    ((BinaryKeyDistribution), LweSecretKeyGenerationFixture, (LweSecretKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweSeededBootstrapKeyGenerationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweSeededBootstrapKeyToLweBootstrapKeyTransformationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey, LweBootstrapKey)),
    ((BinaryKeyDistribution), LweSeededCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweSeededCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextToLweCiphertextTransformationFixture, (Plaintext, LweSecretKey, LweSeededCiphertext, LweCiphertext)),
    ((BinaryKeyDistribution), LweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector)),
    ((BinaryKeyDistribution), LweSeededCiphertextVectorToLweCiphertextVectorTransformationFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector, LweCiphertextVector)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweSeededKeyswitchKeyGenerationFixture, (LweSecretKey, LweSecretKey, LweSeededKeyswitchKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationFixture,(LweSecretKey, LweSecretKey, LweSeededKeyswitchKey, LweKeyswitchKey)),
    ((BinaryKeyDistribution), LweToGlweSecretKeyTransformationFixture, (LweSecretKey, GlweSecretKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweCiphertextVectorGlweCiphertextDiscardingPrivateFunctionalPackingKeyswitchFixture,
        (LweCiphertextVector, LwePrivateFunctionalPackingKeyswitchKey, GlweCiphertext,
            CleartextVector)),
    ((), PlaintextCreationFixture, (Plaintext)),
    ((), PlaintextDiscardingRetrievalFixture, (Plaintext)),
    ((), PlaintextRetrievalFixture, (Plaintext)),
    ((), PlaintextVectorDiscardingRetrievalFixture, (PlaintextVector)),
    ((), PlaintextVectorCreationFixture, (PlaintextVector)),
    ((), PlaintextVectorRetrievalFixture, (PlaintextVector))
}

#[cfg(feature = "backend_default_parallel")]
macro_rules! bench_parallel {
    (($($key_dist:ident),*), $fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, ($($key_dist,)*), DefaultParallelEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($((($($key_dist:ident),*), $fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_parallel() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench_parallel!{($($key_dist),*), $fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench_parallel!{($($key_dist),*), $fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_default_parallel")]
bench_parallel! {
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweBootstrapKeyGenerationFixture, (LweSecretKey, GlweSecretKey, LweBootstrapKey)),
    ((BinaryKeyDistribution, BinaryKeyDistribution), LweSeededBootstrapKeyGenerationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey))
}
