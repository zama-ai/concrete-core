use crate::generation::prototypes::{
    LweCiphertextPrototype, ProtoBinaryLweCiphertext32, ProtoBinaryLweCiphertext64,
    ProtoPlaintext32, ProtoPlaintext64,
};
use crate::generation::prototyping::lwe_secret_key::PrototypesLweSecretKey;
use crate::generation::prototyping::plaintext::PrototypesPlaintext;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::{
    LweCiphertextConsumingRetrievalEngine, LweCiphertextCreationEngine,
    LweCiphertextDecryptionEngine, LweCiphertextEncryptionEngine,
    LweCiphertextTrivialDecryptionEngine, LweCiphertextTrivialEncryptionEngine,
    PlaintextCreationEngine,
};

/// A trait allowing to manipulate LWE ciphertext prototypes.
pub trait PrototypesLweCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>: PrototypesPlaintext<Precision> + PrototypesLweSecretKey<Precision, KeyDistribution>
{
    type LweCiphertextProto: LweCiphertextPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn trivially_encrypt_zero_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Self::LweCiphertextProto;
    fn trivially_encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext: &Self::PlaintextProto,
    ) -> Self::LweCiphertextProto;
    fn encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweCiphertextProto;
    fn decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto;
    fn trivially_decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto;
    fn transform_raw_vec_to_lwe_ciphertext(
        &mut self,
        raw: &[Precision::Raw],
    ) -> Self::LweCiphertextProto;
    fn transform_lwe_ciphertext_to_raw_vec(
        &mut self,
        ciphertext_view: &Self::LweCiphertextProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesLweCiphertext<Precision32, BinaryKeyDistribution> for Maker {
    type LweCiphertextProto = ProtoBinaryLweCiphertext32;

    fn trivially_encrypt_zero_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Self::LweCiphertextProto {
        let plaintext = self.default_engine.create_plaintext(&0u32).unwrap();
        ProtoBinaryLweCiphertext32(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext)
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext: &Self::PlaintextProto,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext32(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext.0)
                .unwrap(),
        )
    }

    fn encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext32(
            self.default_engine
                .encrypt_lwe_ciphertext(&secret_key.0, &plaintext.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto {
        ProtoPlaintext32(
            self.default_engine
                .decrypt_lwe_ciphertext(&secret_key.0, &ciphertext.0)
                .unwrap(),
        )
    }

    fn trivially_decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto {
        ProtoPlaintext32(
            self.default_engine
                .trivially_decrypt_lwe_ciphertext(&ciphertext.0)
                .unwrap(),
        )
    }

    fn transform_raw_vec_to_lwe_ciphertext(&mut self, raw: &[u32]) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext32(
            self.default_engine
                .create_lwe_ciphertext(raw.to_owned())
                .unwrap(),
        )
    }

    fn transform_lwe_ciphertext_to_raw_vec(
        &mut self,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Vec<u32> {
        let ciphertext = ciphertext.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_ciphertext(ciphertext)
            .unwrap()
    }
}

impl PrototypesLweCiphertext<Precision64, BinaryKeyDistribution> for Maker {
    type LweCiphertextProto = ProtoBinaryLweCiphertext64;

    fn trivially_encrypt_zero_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Self::LweCiphertextProto {
        let plaintext = self.default_engine.create_plaintext(&0u64).unwrap();
        ProtoBinaryLweCiphertext64(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext)
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        lwe_dimension: LweDimension,
        plaintext: &Self::PlaintextProto,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext64(
            self.default_engine
                .trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &plaintext.0)
                .unwrap(),
        )
    }

    fn encrypt_plaintext_to_lwe_ciphertext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
    ) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext64(
            self.default_engine
                .encrypt_lwe_ciphertext(&secret_key.0, &plaintext.0, noise)
                .unwrap(),
        )
    }

    fn decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto {
        ProtoPlaintext64(
            self.default_engine
                .decrypt_lwe_ciphertext(&secret_key.0, &ciphertext.0)
                .unwrap(),
        )
    }

    fn trivially_decrypt_lwe_ciphertext_to_plaintext(
        &mut self,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Self::PlaintextProto {
        ProtoPlaintext64(
            self.default_engine
                .trivially_decrypt_lwe_ciphertext(&ciphertext.0)
                .unwrap(),
        )
    }

    fn transform_raw_vec_to_lwe_ciphertext(&mut self, raw: &[u64]) -> Self::LweCiphertextProto {
        ProtoBinaryLweCiphertext64(
            self.default_engine
                .create_lwe_ciphertext(raw.to_owned())
                .unwrap(),
        )
    }

    fn transform_lwe_ciphertext_to_raw_vec(
        &mut self,
        ciphertext: &Self::LweCiphertextProto,
    ) -> Vec<u64> {
        let ciphertext = ciphertext.0.to_owned();
        self.default_engine
            .consume_retrieve_lwe_ciphertext(ciphertext)
            .unwrap()
    }
}
