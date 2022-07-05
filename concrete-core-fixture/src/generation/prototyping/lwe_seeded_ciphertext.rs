use crate::generation::prototypes::{
    LweSeededCiphertextPrototype, ProtoBinaryLweCiphertext32, ProtoBinaryLweCiphertext64,
    ProtoBinaryLweSeededCiphertext32, ProtoBinaryLweSeededCiphertext64,
};
use crate::generation::prototyping::lwe_ciphertext::PrototypesLweCiphertext;
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::plaintext::PrototypesPlaintext;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::dispersion::Variance;
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{
    LweSeededCiphertextEncryptionEngine, LweSeededCiphertextToLweCiphertextTransformationEngine,
};

/// A trait allowing to manipulate LWE ciphertext prototypes.
pub trait PrototypesLweSeededCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintext<Precision>
    + PrototypesLweSecretKey<Precision, KeyDistribution>
    + PrototypesLweCiphertext<Precision, KeyDistribution>
{
    type LweSeededCiphertextProto: LweSeededCiphertextPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_to_lwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextProto;
    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::LweSeededCiphertextProto,
    ) -> Self::LweCiphertextProto;
}

impl PrototypesLweSeededCiphertext<Precision32, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextProto = ProtoBinaryLweSeededCiphertext32;

    fn encrypt_plaintext_to_lwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextProto {
        ProtoBinaryLweSeededCiphertext32(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext(&secret_key.0, &plaintext.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::LweSeededCiphertextProto,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext32(
            self.default_engine
                .transform_lwe_seeded_ciphertext_to_lwe_ciphertext(seeded_ciphertext.0.to_owned())
                .unwrap(),
        )
    }
}

impl PrototypesLweSeededCiphertext<Precision64, BinaryKeyDistribution> for Maker {
    type LweSeededCiphertextProto = ProtoBinaryLweSeededCiphertext64;

    fn encrypt_plaintext_to_lwe_seeded_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweSeededCiphertextProto {
        ProtoBinaryLweSeededCiphertext64(
            self.default_engine
                .encrypt_lwe_seeded_ciphertext(&secret_key.0, &plaintext.0, noise)
                .unwrap(),
        )
    }

    fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext(
        &mut self,
        seeded_ciphertext: &Self::LweSeededCiphertextProto,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext64(
            self.default_engine
                .transform_lwe_seeded_ciphertext_to_lwe_ciphertext(seeded_ciphertext.0.to_owned())
                .unwrap(),
        )
    }
}
