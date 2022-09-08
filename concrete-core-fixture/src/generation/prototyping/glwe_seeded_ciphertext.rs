use crate::generation::prototypes::{
    GlweSeededCiphertextPrototype, ProtoBinaryGlweCiphertext32, ProtoBinaryGlweCiphertext64,
    ProtoBinaryGlweSeededCiphertext32, ProtoBinaryGlweSeededCiphertext64,
};
use crate::generation::prototyping::glwe_ciphertext::PrototypesGlweCiphertext;
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext_vector::PrototypesPlaintextVector;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    GlweSeededCiphertextEncryptionEngine, GlweSeededCiphertextToGlweCiphertextTransformationEngine,
    Variance,
};

/// A trait allowing to manipulate seeded GLWE ciphertext prototypes.
pub trait PrototypesGlweSeededCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextVector<Precision>
    + PrototypesGlweSecretKey<Precision, KeyDistribution>
    + PrototypesGlweCiphertext<Precision, KeyDistribution>
{
    type GlweSeededCiphertextProto: GlweSeededCiphertextPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextProto;
    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextProto,
    ) -> Self::GlweCiphertextProto;
}

impl PrototypesGlweSeededCiphertext<Precision32, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextProto = ProtoBinaryGlweSeededCiphertext32;

    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextProto {
        ProtoBinaryGlweSeededCiphertext32(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextProto,
    ) -> ProtoBinaryGlweCiphertext32 {
        ProtoBinaryGlweCiphertext32(
            self.default_engine
                .transform_glwe_seeded_ciphertext_to_glwe_ciphertext(seeded_ciphertext.0.to_owned())
                .unwrap(),
        )
    }
}

impl PrototypesGlweSeededCiphertext<Precision64, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextProto = ProtoBinaryGlweSeededCiphertext64;

    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextProto {
        ProtoBinaryGlweSeededCiphertext64(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_to_glwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextProto,
    ) -> ProtoBinaryGlweCiphertext64 {
        ProtoBinaryGlweCiphertext64(
            self.default_engine
                .transform_glwe_seeded_ciphertext_to_glwe_ciphertext(seeded_ciphertext.0.to_owned())
                .unwrap(),
        )
    }
}
