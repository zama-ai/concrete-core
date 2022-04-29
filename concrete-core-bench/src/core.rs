use crate::benchmark::BenchmarkFixture;
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32, Precision64};
use criterion::Criterion;
use paste::paste;

macro_rules! bench {
    ($fixture: ident, $precision: ident, ($($types:ident),+), $maker: ident, $engine: ident, $criterion: ident) => {
        paste!{
            <$fixture as BenchmarkFixture<$precision, CoreEngine, ($($types,)+),>>::bench_all_parameters(
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
            let mut engine = CoreEngine::new(()).unwrap();
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
    (LweCiphertextDiscardingOppositeFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingOppositeFixture, (LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextFusingAdditionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextVectorTrivialDecryptionFixture, (PlaintextVector, LweCiphertextVector)),
    (LweCiphertextVectorTrivialEncryptionFixture, (PlaintextVector, LweCiphertextVector)),
    (LweCiphertextDiscardingSubtractionFixture, (LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingDecryptionFixture, (LweCiphertext, LweSecretKey, Plaintext)),
    (LweCiphertextPlaintextDiscardingAdditionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextFusingAdditionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextDiscardingSubtractionFixture, (LweCiphertext, Plaintext, LweCiphertext)),
    (LweCiphertextPlaintextFusingSubtractionFixture, (Plaintext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture1, (FourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture2, (FourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertext)),
    (LweCiphertextDiscardingBootstrapFixture1, (FourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingBootstrapFixture2, (FourierLweBootstrapKey, GlweCiphertextView, LweCiphertextView, LweCiphertextMutView)),
    (LweCiphertextDiscardingExtractionFixture, (GlweCiphertext, LweCiphertext)),
    (LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchFixture, (LweCiphertextVector,
        PackingKeyswitchKey, GlweCiphertext)),
    (LweCiphertextCreationFixture, (LweCiphertext, Vec)),
    (LweCiphertextCreationFixture, (LweCiphertextView, Slice)),
    (LweCiphertextCreationFixture, (LweCiphertextMutView, MutSlice)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertext, Vec)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertextView, Slice)),
    (LweCiphertextConsumingRetrievalFixture, (LweCiphertextMutView, MutSlice)),
    (PlaintextCreationFixture, (Plaintext)),
    (PlaintextDiscardingRetrievalFixture, (Plaintext)),
    (PlaintextRetrievalFixture, (Plaintext)),
    (PlaintextVectorDiscardingRetrievalFixture, (PlaintextVector)),
    (PlaintextVectorCreationFixture, (PlaintextVector)),
    (PlaintextVectorRetrievalFixture, (PlaintextVector)),
    (GlweCiphertextGgswCiphertextExternalProductFixture, (GlweCiphertext, FourierGgswCiphertext, GlweCiphertext)),
    (GlweCiphertextGgswCiphertextDiscardingExternalProductFixture, (GlweCiphertext, FourierGgswCiphertext, GlweCiphertext))
}
