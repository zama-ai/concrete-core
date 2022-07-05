use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use concrete_csprng::seeders::UnixSeeder;
use criterion::Criterion;

use paste::paste;

macro_rules! bench {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, DefaultEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
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
    (CleartextCreationFixture, (Cleartext)),
    (CleartextRetrievalFixture, (Cleartext)),
    (CleartextDiscardingRetrievalFixture, (Cleartext)),
    (CleartextVectorCreationFixture, (CleartextVector)),
    (GlweCiphertextTrivialDecryptionFixture, (PlaintextVector, GlweCiphertext)),
    (CleartextVectorDiscardingRetrievalFixture, (CleartextVector)),
    (CleartextVectorRetrievalFixture, (CleartextVector)),
    (GlweCiphertextDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextDiscardingDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextVector, GlweCiphertext)),
    (GlweCiphertextDiscardingTrivialEncryptionFixture, (PlaintextVector, GlweCiphertextMutView)),
    (GlweCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextTrivialEncryptionFixture, (PlaintextVector, GlweCiphertext)),
    (GlweCiphertextZeroEncryptionFixture, (GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    (GlweCiphertextVectorDecryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    (GlweCiphertextVectorTrivialDecryptionFixture, (PlaintextVector, GlweCiphertextVector)),
    (GlweCiphertextVectorTrivialEncryptionFixture, (PlaintextVector, GlweCiphertextVector)),
    (GlweCiphertextVectorDiscardingDecryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    (GlweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    (GlweCiphertextVectorZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextVector)),
    (GlweCiphertextCreationFixture, (GlweCiphertext, Vec)),
    (GlweCiphertextCreationFixture, (GlweCiphertextView, Slice)),
    (GlweCiphertextCreationFixture, (GlweCiphertextMutView, MutSlice)),
    (GlweCiphertextConsumingRetrievalFixture, (GlweCiphertext, Vec)),
    (GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextView, Slice)),
    (GlweCiphertextConsumingRetrievalFixture, (GlweCiphertextMutView, MutSlice)),
    (GlweSecretKeyCreationFixture, (GlweSecretKey)),
    (GlweSeededCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext)),
    (GlweSeededCiphertextToGlweCiphertextTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertext, GlweCiphertext)),
    (GlweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector)),
    (GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationFixture, (PlaintextVector, GlweSecretKey, GlweSeededCiphertextVector, GlweCiphertextVector)),
    (GlweToLweSecretKeyTransformationFixture, (GlweSecretKey, LweSecretKey)),
    (LweBootstrapKeyCreationFixture, (LweSecretKey, GlweSecretKey, LweBootstrapKey)),
    (LweCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    (LweCiphertextZeroEncryptionFixture, (LweSecretKey, LweCiphertext)),
    (LweCiphertextTrivialEncryptionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextTrivialDecryptionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextVectorZeroEncryptionFixture, (LweSecretKey, LweCiphertextVector)),
    (LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    (LweCiphertextDecryptionFixture, (Plaintext, LweSecretKey, LweCiphertextView)),
    (LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    (LweCiphertextDiscardingEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertextMutView)),
    (LweCiphertextVectorDecryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    (LweCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    (LweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, LweSecretKey,
        LweCiphertextVector)),
    (LweCiphertextVectorDiscardingDecryptionFixture, (PlaintextVector, LweSecretKey,
        LweCiphertextVector)),
    (LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertext, Cleartext, LweCiphertext)),
    (LweCiphertextCleartextDiscardingMultiplicationFixture, (LweCiphertextView, Cleartext, LweCiphertextMutView)),
    (LweCiphertextCleartextFusingMultiplicationFixture, (LweCiphertext, Cleartext)),
    (LweCiphertextFusingOppositeFixture, (LweCiphertext)),
    (LweCiphertextFusingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextVectorFusingAdditionFixture, (LweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextVectorFusingSubtractionFixture, (LweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextVectorDiscardingSubtractionFixture, (LweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextVectorDiscardingAdditionFixture, (LweCiphertextVector, LweCiphertextVector)),
    (LweCiphertextVectorDiscardingAffineTransformationFixture, (LweCiphertextVector, CleartextVector, Plaintext, LweCiphertext)),
    (LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingKeyswitchFixture, (LweKeyswitchKey, LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingAdditionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingAdditionFixture, (LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingOppositeFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingOppositeFixture, (LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextFusingAdditionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextVectorTrivialDecryptionFixture, (PlaintextVector, LweCiphertextVector)),
    (LweCiphertextVectorTrivialEncryptionFixture, (PlaintextVector, LweCiphertextVector)),
    (LweCiphertextDiscardingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingDecryptionFixture, (LweCiphertext, LweSecretKey, Plaintext)),
    (LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertextView, Plaintext, LweCiphertextMutView)),
    (LweCiphertextPlaintextFusingAdditionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextDiscardingSubtractionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextFusingSubtractionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextDiscardingExtractionFixture, (GlweCiphertext, LweCiphertext)),
    (LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchFixture, (LweCiphertextVector,
        PackingKeyswitchKey, GlweCiphertext)),
    (LweCiphertextCreationFixture, (LweCiphertext, Vec)),
    (LweCiphertextCreationFixture, (LweCiphertextView, Slice)),
    (LweCiphertextCreationFixture, (LweCiphertextMutView, MutSlice)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertext, Vec)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertextView, Slice)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertextMutView, MutSlice)),
    (LweKeyswitchKeyCreationFixture, (LweSecretKey, LweSecretKey, LweKeyswitchKey)),
    (LweSecretKeyCreationFixture, (LweSecretKey)),
    (LweSeededBootstrapKeyCreationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey)),
    (LweSeededBootstrapKeyToLweBootstrapKeyTransformationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey, LweBootstrapKey)),
    (LweSeededCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweSeededCiphertext)),
    (LweSeededCiphertextToLweCiphertextTransformationFixture, (Plaintext, LweSecretKey, LweSeededCiphertext, LweCiphertext)),
    (LweSeededCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector)),
    (LweSeededCiphertextVectorToLweCiphertextVectorTransformationFixture, (PlaintextVector, LweSecretKey, LweSeededCiphertextVector, LweCiphertextVector)),
    (LweSeededKeyswitchKeyCreationFixture, (LweSecretKey, LweSecretKey, LweSeededKeyswitchKey)),
    (LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationFixture,(LweSecretKey, LweSecretKey, LweSeededKeyswitchKey, LweKeyswitchKey)),
    (LweToGlweSecretKeyTransformationFixture, (LweSecretKey, GlweSecretKey)),
    (PlaintextCreationFixture, (Plaintext)),
    (PlaintextDiscardingRetrievalFixture, (Plaintext)),
    (PlaintextRetrievalFixture, (Plaintext)),
    (PlaintextVectorDiscardingRetrievalFixture, (PlaintextVector)),
    (PlaintextVectorCreationFixture, (PlaintextVector)),
    (PlaintextVectorRetrievalFixture, (PlaintextVector))
}

#[cfg(feature = "backend_default_parallel")]
macro_rules! bench_parallel {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, DefaultParallelEngine, ($($types,)+),
            >>::bench_all_parameters(
                &mut $maker,
                &mut $engine,
                &mut $criterion,
                None
            );
        }
    };
    ($(($fixture: ident, ($($types:ident),+))),+) => {
        pub fn bench_parallel() {
            let mut criterion = Criterion::default().configure_from_args();
            let mut maker = Maker::default();
            let mut engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench_parallel!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench_parallel!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

#[cfg(feature = "backend_default_parallel")]
bench_parallel! {
    (LweBootstrapKeyCreationFixture, (LweSecretKey, GlweSecretKey, LweBootstrapKey)),
    (LweSeededBootstrapKeyCreationFixture, (LweSecretKey, GlweSecretKey, LweSeededBootstrapKey))
}
