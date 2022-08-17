use crate::generation::prototypes::{
    LweSeededCiphertextVectorPrototype, ProtoBinaryLweCiphertextVector32,
    ProtoBinaryLweCiphertextVector64, ProtoBinaryLweSeededCiphertextVector32,
    ProtoBinaryLweSeededCiphertextVector64,
};
use crate::generation::prototyping::lwe_ciphertext_vector::PrototypesLweCiphertextVector;
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::plaintext_vector::PrototypesPlaintextVector;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::dispersion::Variance;
use concrete_core::prelude::{
    LweSeededCiphertextVectorEncryptionEngine,
    LweSeededCiphertextVectorToLweCiphertextVectorTransformationEngine,
};

/// A trait allowing to manipulate LWE seeded ciphertext vector prototypes.
pub trait PrototypesLweSeededCiphertextVector<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextVector<Precision>
    + PrototypesLweSecretKey<Precision, KeyDistribution>
    + PrototypesLweCiphertextVector<Precision, KeyDistribution>
{
    type LweSeededCiphertextVectorProto: LweSeededCiphertextVectorPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_vector_to_lwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextVectorProto;
    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext_vector: &Self::LweSeededCiphertextVectorProto,
    ) -> Self::LweCiphertextVectorProto;
}

impl PrototypesLweSeededCiphertextVector<Precision32, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextVectorProto = ProtoBinaryLweSeededCiphertextVector32;

    fn encrypt_plaintext_vector_to_lwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextVectorProto {
        ProtoBinaryLweSeededCiphertextVector32(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext_vector(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext_vector: &Self::LweSeededCiphertextVectorProto,
    ) -> Self::LweCiphertextVectorProto {
        ProtoBinaryLweCiphertextVector32(
            self.default_engine
                .transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
                    seeded_ciphertext_vector.0.to_owned(),
                )
                .unwrap(),
        )
    }
}

impl PrototypesLweSeededCiphertextVector<Precision64, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextVectorProto = ProtoBinaryLweSeededCiphertextVector64;

    fn encrypt_plaintext_vector_to_lwe_seeded_ciphertext_vector(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_vector: &Self::PlaintextVectorProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextVectorProto {
        ProtoBinaryLweSeededCiphertextVector64(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext_vector(&secret_key.0, &plaintext_vector.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
        &mut self,
        seeded_ciphertext_vector: &Self::LweSeededCiphertextVectorProto,
    ) -> Self::LweCiphertextVectorProto {
        ProtoBinaryLweCiphertextVector64(
            self.default_engine
                .transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
                    seeded_ciphertext_vector.0.to_owned(),
                )
                .unwrap(),
        )
    }
}
