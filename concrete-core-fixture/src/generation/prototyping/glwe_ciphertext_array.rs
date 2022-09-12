use crate::generation::prototypes::{
    GlweCiphertextArrayPrototype, ProtoBinaryGlweCiphertextArray32,
    ProtoBinaryGlweCiphertextArray64, ProtoPlaintextArray32, ProtoPlaintextArray64,
};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext_array::PrototypesPlaintextArray;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    GlweCiphertextArrayDecryptionEngine, GlweCiphertextArrayEncryptionEngine,
    GlweCiphertextArrayTrivialDecryptionEngine, GlweCiphertextArrayTrivialEncryptionEngine,
    GlweCiphertextCount, GlweSize, PlaintextArrayCreationEngine, PlaintextCount, Variance,
};

/// A trait allowing to manipulate GLWE ciphertext array prototypes.
pub trait PrototypesGlweCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextArray<Precision> + PrototypesGlweSecretKey<Precision, KeyDistribution>
{
    type GlweCiphertextArrayProto: GlweCiphertextArrayPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn trivially_encrypt_zeros_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_count: PlaintextCount,
    ) -> Self::GlweCiphertextArrayProto;
    fn trivially_encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::GlweCiphertextArrayProto;

    fn trivially_decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto;

    fn encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweCiphertextArrayProto;

    fn decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto;
}

impl PrototypesGlweCiphertextArray<Precision32, BinaryKeyDistribution> for Maker {
    type GlweCiphertextArrayProto = ProtoBinaryGlweCiphertextArray32;

    fn trivially_encrypt_zeros_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_count: PlaintextCount,
    ) -> Self::GlweCiphertextArrayProto {
        let plaintext_array = self
            .default_engine
            .create_plaintext_array_from(&vec![0u32; plaintext_count.0])
            .unwrap();
        ProtoBinaryGlweCiphertextArray32(
            self.default_engine
                .trivially_encrypt_glwe_ciphertext_array(
                    glwe_size,
                    glwe_ciphertext_count,
                    &plaintext_array,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::GlweCiphertextArrayProto {
        ProtoBinaryGlweCiphertextArray32(
            self.default_engine
                .trivially_encrypt_glwe_ciphertext_array(
                    glwe_size,
                    glwe_ciphertext_count,
                    &plaintext_array.0,
                )
                .unwrap(),
        )
    }

    fn trivially_decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray32(
            self.default_engine
                .trivially_decrypt_glwe_ciphertext_array(&ciphertext.0)
                .unwrap(),
        )
    }

    fn encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweCiphertextArrayProto {
        ProtoBinaryGlweCiphertextArray32(
            self.default_engine
                .encrypt_glwe_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray32(
            self.default_engine
                .decrypt_glwe_ciphertext_array(&secret_key.0, &ciphertext.0)
                .unwrap(),
        )
    }
}

impl PrototypesGlweCiphertextArray<Precision64, BinaryKeyDistribution> for Maker {
    type GlweCiphertextArrayProto = ProtoBinaryGlweCiphertextArray64;

    fn trivially_encrypt_zeros_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_count: PlaintextCount,
    ) -> Self::GlweCiphertextArrayProto {
        let plaintext_array = self
            .default_engine
            .create_plaintext_array_from(&vec![0u64; plaintext_count.0])
            .unwrap();
        ProtoBinaryGlweCiphertextArray64(
            self.default_engine
                .trivially_encrypt_glwe_ciphertext_array(
                    glwe_size,
                    glwe_ciphertext_count,
                    &plaintext_array,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::GlweCiphertextArrayProto {
        ProtoBinaryGlweCiphertextArray64(
            self.default_engine
                .trivially_encrypt_glwe_ciphertext_array(
                    glwe_size,
                    glwe_ciphertext_count,
                    &plaintext_array.0,
                )
                .unwrap(),
        )
    }

    fn trivially_decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray64(
            self.default_engine
                .trivially_decrypt_glwe_ciphertext_array(&ciphertext.0)
                .unwrap(),
        )
    }
    fn encrypt_plaintext_array_to_glwe_ciphertext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::GlweCiphertextArrayProto {
        ProtoBinaryGlweCiphertextArray64(
            self.default_engine
                .encrypt_glwe_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_glwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        ciphertext: &Self::GlweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray64(
            self.default_engine
                .decrypt_glwe_ciphertext_array(&secret_key.0, &ciphertext.0)
                .unwrap(),
        )
    }
}
