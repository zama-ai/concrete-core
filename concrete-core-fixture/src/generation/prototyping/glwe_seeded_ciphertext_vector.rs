use crate::generation::prototypes::{
    GlweSeededCiphertextVectorPrototype, ProtoBinaryGlweCiphertextVector32,
    ProtoBinaryGlweCiphertextVector64, ProtoBinaryGlweSeededCiphertextVector32,
    ProtoBinaryGlweSeededCiphertextVector64,
};
use crate::generation::prototyping::glwe_ciphertext_vector::PrototypesGlweCiphertextVector;
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext_vector::PrototypesPlaintextVector;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::dispersion::Variance;
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{
    GlweSeededCiphertextVectorEncryptionEngine,
    GlweSeededCiphertextVectorToGlweCiphertextVectorTransformationEngine,
};

/// A trait allowing to manipulate seeded GLWE ciphertext vector prototypes.
pub trait PrototypesGlweSeededCiphertextVector<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextVector<Precision>
    + PrototypesGlweSecretKey<Precision, KeyDistribution>
    + PrototypesGlweCiphertextVector<Precision, KeyDistribution>
{
    type GlweSeededCiphertextVectorProto: GlweSeededCiphertextVectorPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextVectorProto;
    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext_vector: &Self::GlweSeededCiphertextVectorProto,
    ) -> Self::GlweCiphertextVectorProto;
}

impl PrototypesGlweSeededCiphertextVector<Precision32, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextVectorProto = ProtoBinaryGlweSeededCiphertextVector32;

    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextVectorProto {
        ProtoBinaryGlweSeededCiphertextVector32(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext_vector(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextVectorProto,
    ) -> ProtoBinaryGlweCiphertextVector32 {
        ProtoBinaryGlweCiphertextVector32(
            self.default_engine
                .transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
                    seeded_ciphertext.0.to_owned(),
                )
                .unwrap(),
        )
    }
}

impl PrototypesGlweSeededCiphertextVector<Precision64, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextVectorProto = ProtoBinaryGlweSeededCiphertextVector64;

    fn encrypt_plaintext_vector_to_glwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextVectorProto {
        ProtoBinaryGlweSeededCiphertextVector64(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext_vector(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextVectorProto,
    ) -> ProtoBinaryGlweCiphertextVector64 {
        ProtoBinaryGlweCiphertextVector64(
            self.default_engine
                .transform_glwe_seeded_ciphertext_vector_to_glwe_ciphertext_vector(
                    seeded_ciphertext.0.to_owned(),
                )
                .unwrap(),
        )
    }
}
