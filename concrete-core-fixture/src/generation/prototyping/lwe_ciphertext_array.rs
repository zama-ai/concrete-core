use crate::generation::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{
    LweCiphertextArrayDecryptionEngine, LweCiphertextArrayEncryptionEngine,
    LweCiphertextArrayTrivialDecryptionEngine, LweCiphertextArrayTrivialEncryptionEngine,
    LweCiphertextCount, LweDimension, PlaintextArrayCreationEngine, Variance,
};

use crate::generation::prototypes::{
    LweCiphertextArrayPrototype, ProtoBinaryLweCiphertextArray32, ProtoBinaryLweCiphertextArray64,
    ProtoPlaintextArray32, ProtoPlaintextArray64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::plaintext_array::PrototypesPlaintextArray;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};

/// A trait allowing to manipulate lwe ciphertext array prototypes.
pub trait PrototypesLweCiphertextArray<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesPlaintextArray<Precision> + PrototypesLweSecretKey<Precision, KeyDistribution>
{
    type LweCiphertextArrayProto: LweCiphertextArrayPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn trivially_encrypt_zeros_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        count: LweCiphertextCount,
    ) -> Self::LweCiphertextArrayProto;

    fn trivially_encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::LweCiphertextArrayProto;

    fn encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweCiphertextArrayProto;

    fn decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext_array: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto;

    fn trivially_decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto;
}

impl PrototypesLweCiphertextArray<Precision32, BinaryKeyDistribution> for Maker {
    type LweCiphertextArrayProto = ProtoBinaryLweCiphertextArray32;

    fn trivially_encrypt_zeros_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        count: LweCiphertextCount,
    ) -> Self::LweCiphertextArrayProto {
        let plaintext_array = self
            .default_engine
            .create_plaintext_array_from(&vec![0u32; count.0])
            .unwrap();
        ProtoBinaryLweCiphertextArray32(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext_array(
                    lwe_dimension.to_lwe_size(),
                    &plaintext_array,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray32(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext_array(
                    lwe_dimension.to_lwe_size(),
                    &plaintext_array.0,
                )
                .unwrap(),
        )
    }

    fn encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray32(
            self.default_engine
                .encrypt_lwe_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext_array: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray32(
            self.default_engine
                .decrypt_lwe_ciphertext_array(&secret_key.0, &ciphertext_array.0)
                .unwrap(),
        )
    }

    fn trivially_decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext_array: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray32(
            self.default_engine
                .trivially_decrypt_lwe_ciphertext_array(&ciphertext_array.0)
                .unwrap(),
        )
    }
}

impl PrototypesLweCiphertextArray<Precision64, BinaryKeyDistribution> for Maker {
    type LweCiphertextArrayProto = ProtoBinaryLweCiphertextArray64;

    fn trivially_encrypt_zeros_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        count: LweCiphertextCount,
    ) -> Self::LweCiphertextArrayProto {
        let plaintext_array = self
            .default_engine
            .create_plaintext_array_from(&vec![0u64; count.0])
            .unwrap();
        ProtoBinaryLweCiphertextArray64(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext_array(
                    lwe_dimension.to_lwe_size(),
                    &plaintext_array,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext_array: &Self::PlaintextArrayProto,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray64(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext_array(
                    lwe_dimension.to_lwe_size(),
                    &plaintext_array.0,
                )
                .unwrap(),
        )
    }

    fn encrypt_plaintext_array_to_lwe_ciphertext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext_array: &Self::PlaintextArrayProto,
        noise: Variance,
    ) -> Self::LweCiphertextArrayProto {
        ProtoBinaryLweCiphertextArray64(
            self.default_engine
                .encrypt_lwe_ciphertext_array(&secret_key.0, &plaintext_array.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext_array: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray64(
            self.default_engine
                .decrypt_lwe_ciphertext_array(&secret_key.0, &ciphertext_array.0)
                .unwrap(),
        )
    }

    fn trivially_decrypt_lwe_ciphertext_array_to_plaintext_array(
        &mut self,
        ciphertext_array: &Self::LweCiphertextArrayProto,
    ) -> Self::PlaintextArrayProto {
        ProtoPlaintextArray64(
            self.default_engine
                .trivially_decrypt_lwe_ciphertext_array(&ciphertext_array.0)
                .unwrap(),
        )
    }
}
