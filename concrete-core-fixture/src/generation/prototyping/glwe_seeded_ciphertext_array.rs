use crate::generation::prototypes::{
    GlweSeededCiphertextArrayPrototype, ProtoBinaryGlweCiphertextArray32,
    ProtoBinaryGlweCiphertextArray64, ProtoBinaryGlweSeededCiphertextArray32,
    ProtoBinaryGlweSeededCiphertextArray64,
};
use crate::generation::prototyping::glwe_ciphertext_array::PrototypesGlweCiphertextArray;
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext_array::PrototypesPlaintextArray;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    GlweSeededCiphertextArrayEncryptionEngine,
    GlweSeededCiphertextArrayToGlweCiphertextArrayTransformationEngine, Variance,
};

/// A trait allowing to manipulate seeded GLWE ciphertext array prototypes.
pub trait PrototypesGlweSeededCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextArray<Precision>
    + PrototypesGlweSecretKey<Precision, KeyDistribution>
    + PrototypesGlweCiphertextArray<Precision, KeyDistribution>
{
    type GlweSeededCiphertextArrayProto: GlweSeededCiphertextArrayPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn encrypt_plaintext_array_to_glwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextArrayProto;
    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        seeded_ciphertext_array: &Self::GlweSeededCiphertextArrayProto,
    ) -> Self::GlweCiphertextArrayProto;
}

impl PrototypesGlweSeededCiphertextArray<Precision32, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextArrayProto = ProtoBinaryGlweSeededCiphertextArray32;

    fn encrypt_plaintext_array_to_glwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextArrayProto {
        ProtoBinaryGlweSeededCiphertextArray32(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextArrayProto,
    ) -> ProtoBinaryGlweCiphertextArray32 {
        ProtoBinaryGlweCiphertextArray32(
            self.default_engine
                .transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
                    seeded_ciphertext.0.to_owned(),
                )
                .unwrap(),
        )
    }
}

impl PrototypesGlweSeededCiphertextArray<Precision64, BinaryKeyDistribution> for Maker {
    type GlweSeededCiphertextArrayProto = ProtoBinaryGlweSeededCiphertextArray64;

    fn encrypt_plaintext_array_to_glwe_seeded_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweSeededCiphertextArrayProto {
        ProtoBinaryGlweSeededCiphertextArray64(
            self.default_engine
                .encrypt_glwe_seeded_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
        &mut self,
        seeded_ciphertext: &Self::GlweSeededCiphertextArrayProto,
    ) -> ProtoBinaryGlweCiphertextArray64 {
        ProtoBinaryGlweCiphertextArray64(
            self.default_engine
                .transform_glwe_seeded_ciphertext_array_to_glwe_ciphertext_array(
                    seeded_ciphertext.0.to_owned(),
                )
                .unwrap(),
        )
    }
}
