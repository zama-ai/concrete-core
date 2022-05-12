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
            <$fixture as BenchmarkFixture<$precision, AesniEngine, ($($types,)+),
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
            let mut engine = AesniEngine::new(Box::new(UnixSeeder::new(0))).unwrap();
            $(
                paste!{
                    bench!{$fixture, Precision32, ($([< $types 32 >]),+), maker, engine, criterion}
                    bench!{$fixture, Precision64, ($([< $types 64 >]),+), maker, engine, criterion}
                }
            )+
        }
    };
}

bench! {
    (GlweCiphertextDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextVectorDiscardingEncryptionFixture, (PlaintextVector, GlweSecretKey,
        GlweCiphertextVector)),
    (GlweCiphertextZeroEncryptionFixture, (GlweSecretKey, GlweCiphertext)),
    (GlweCiphertextVectorZeroEncryptionFixture, (GlweSecretKey, GlweCiphertextVector)),
    (GlweCiphertextVectorEncryptionFixture, (PlaintextVector, GlweSecretKey, GlweCiphertextVector)),
    (GlweSecretKeyCreationFixture, (GlweSecretKey)),
    (LweCiphertextEncryptionFixture, (Plaintext, LweSecretKey, LweCiphertext)),
    (LweCiphertextZeroEncryptionFixture, (LweSecretKey, LweCiphertext)),
    (LweCiphertextVectorEncryptionFixture, (PlaintextVector, LweSecretKey, LweCiphertextVector)),
    (LweCiphertextVectorZeroEncryptionFixture, (LweSecretKey, LweCiphertextVector)),
    (LweBootstrapKeyCreationFixture, (LweSecretKey, GlweSecretKey, LweBootstrapKey)),
    (LweKeyswitchKeyCreationFixture, (LweSecretKey, LweSecretKey, LweKeyswitchKey)),
    (LweSecretKeyCreationFixture, (LweSecretKey))
}
