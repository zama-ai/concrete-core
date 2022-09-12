use crate::generation::prototypes::{
    LweSeededCiphertextArrayPrototype, ProtoBinaryLweCiphertextArray32,
    ProtoBinaryLweCiphertextArray64, ProtoBinaryLweSeededCiphertextArray32,
    ProtoBinaryLweSeededCiphertextArray64,
};
use crate::generation::prototyping::lwe_ciphertext_array::PrototypesLweCiphertextArray;
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::plaintext_array::PrototypesPlaintextArray;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    LweSeededCiphertextArrayEncryptionEngine,
    LweSeededCiphertextArrayToLweCiphertextArrayTransformationEngine, Variance,
};

/// A trait allowing to manipulate LWE seeded ciphertext array prototypes.
pub trait PrototypesLweSeededCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextArray<Precision>
    + PrototypesLweSecretKey<Precision, KeyDistribution>
    + PrototypesLweCiphertextArray<Precision, KeyDistribution>
{
    type LweSeededCiphertextArrayProto: LweSeededCiphertextArrayPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_array_to_lwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextArrayProto;
    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        seeded_ciphertext_array: &Self::LweSeededCiphertextArrayProto,
    ) -> Self::LweCiphertextArrayProto;
}

impl PrototypesLweSeededCiphertextArray<Precision32, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextArrayProto = ProtoBinaryLweSeededCiphertextArray32;

    fn encrypt_plaintext_array_to_lwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextArrayProto {
        ProtoBinaryLweSeededCiphertextArray32(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        seeded_ciphertext_array: &Self::LweSeededCiphertextArrayProto,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray32(
            self.default_engine
                .transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
                    seeded_ciphertext_array.0.to_owned(),
                )
                .unwrap(),
        )
    }
}

impl PrototypesLweSeededCiphertextArray<Precision64, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextArrayProto = ProtoBinaryLweSeededCiphertextArray64;

    fn encrypt_plaintext_array_to_lwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextArrayProto {
        ProtoBinaryLweSeededCiphertextArray64(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
        &mut self,
        seeded_ciphertext_array: &Self::LweSeededCiphertextArrayProto,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray64(
            self.default_engine
                .transform_lwe_seeded_ciphertext_array_to_lwe_ciphertext_array(
                    seeded_ciphertext_array.0.to_owned(),
                )
                .unwrap(),
        )
    }
}
