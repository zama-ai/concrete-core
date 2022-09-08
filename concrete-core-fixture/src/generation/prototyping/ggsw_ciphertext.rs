use crate::generation::prototypes::{
    GgswCiphertextPrototype, ProtoBinaryGgswCiphertext32, ProtoBinaryGgswCiphertext64,
};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext::PrototypesPlaintext;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextScalarEncryptionEngine,
    GgswCiphertextScalarTrivialEncryptionEngine, GlweDimension, PlaintextCreationEngine,
    PolynomialSize, Variance,
};

/// A trait allowing to manipulate GGSW ciphertext prototypes.
pub trait PrototypesGgswCiphertext<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>: PrototypesPlaintext<Precision> + PrototypesGlweSecretKey<Precision, KeyDistribution>
{
    type GgswCiphertextProto: GgswCiphertextPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn trivially_encrypt_zero_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto;
    fn trivially_encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        plaintext: &Self::PlaintextProto,
    ) -> Self::GgswCiphertextProto;
    fn encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto;
}

impl PrototypesGgswCiphertext<Precision32, BinaryKeyDistribution> for Maker {
    type GgswCiphertextProto = ProtoBinaryGgswCiphertext32;

    fn trivially_encrypt_zero_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        let plaintext = self.default_engine.create_plaintext_from(&0u32).unwrap();
        ProtoBinaryGgswCiphertext32(
            self.default_engine
                .trivially_encrypt_scalar_ggsw_ciphertext(
                    poly_size,
                    glwe_dimension.to_glwe_size(),
                    decomposition_level_count,
                    decomposition_base_log,
                    &plaintext,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        plaintext: &Self::PlaintextProto,
    ) -> Self::GgswCiphertextProto {
        ProtoBinaryGgswCiphertext32(
            self.default_engine
                .trivially_encrypt_scalar_ggsw_ciphertext(
                    poly_size,
                    glwe_dimension.to_glwe_size(),
                    decomposition_level_count,
                    decomposition_base_log,
                    &plaintext.0,
                )
                .unwrap(),
        )
    }

    fn encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        ProtoBinaryGgswCiphertext32(
            self.default_engine
                .encrypt_scalar_ggsw_ciphertext(
                    &secret_key.0,
                    &plaintext.0,
                    noise,
                    decomposition_level_count,
                    decomposition_base_log,
                )
                .unwrap(),
        )
    }
}

impl PrototypesGgswCiphertext<Precision64, BinaryKeyDistribution> for Maker {
    type GgswCiphertextProto = ProtoBinaryGgswCiphertext64;

    fn trivially_encrypt_zero_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        let plaintext = self.default_engine.create_plaintext_from(&0u64).unwrap();
        ProtoBinaryGgswCiphertext64(
            self.default_engine
                .trivially_encrypt_scalar_ggsw_ciphertext(
                    poly_size,
                    glwe_dimension.to_glwe_size(),
                    decomposition_level_count,
                    decomposition_base_log,
                    &plaintext,
                )
                .unwrap(),
        )
    }

    fn trivially_encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        plaintext: &Self::PlaintextProto,
    ) -> Self::GgswCiphertextProto {
        ProtoBinaryGgswCiphertext64(
            self.default_engine
                .trivially_encrypt_scalar_ggsw_ciphertext(
                    poly_size,
                    glwe_dimension.to_glwe_size(),
                    decomposition_level_count,
                    decomposition_base_log,
                    &plaintext.0,
                )
                .unwrap(),
        )
    }

    fn encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        ProtoBinaryGgswCiphertext64(
            self.default_engine
                .encrypt_scalar_ggsw_ciphertext(
                    &secret_key.0,
                    &plaintext.0,
                    noise,
                    decomposition_level_count,
                    decomposition_base_log,
                )
                .unwrap(),
        )
    }
}
