use crate::generation::prototypes::{
    GgswCiphertextPrototype, ProtoBinaryFourierGgswCiphertext32,
    ProtoBinaryFourierGgswCiphertext64, ProtoBinaryGgswCiphertext32, ProtoBinaryGgswCiphertext64,
};
use crate::generation::prototyping::glwe_secret_key::PrototypesGlweSecretKey;
use crate::generation::prototyping::plaintext::PrototypesPlaintext;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{
    GgswCiphertextConversionEngine, GgswCiphertextScalarEncryptionEngine,
    GgswCiphertextScalarTrivialEncryptionEngine, PlaintextCreationEngine,
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
    type GgswCiphertextProto = ProtoBinaryFourierGgswCiphertext32;

    fn encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        let ggsw = self
            .core_engine
            .encrypt_scalar_ggsw_ciphertext(
                &secret_key.0,
                &plaintext.0,
                noise,
                decomposition_level_count,
                decomposition_base_log,
            )
            .unwrap();
        ProtoBinaryFourierGgswCiphertext32(self.core_engine.convert_ggsw_ciphertext(&ggsw).unwrap())
    }
}

impl PrototypesGgswCiphertext<Precision64, BinaryKeyDistribution> for Maker {
    type GgswCiphertextProto = ProtoBinaryFourierGgswCiphertext64;

    fn encrypt_plaintext_to_ggsw_ciphertext(
        &mut self,
        secret_key: &Self::GlweSecretKeyProto,
        plaintext: &Self::PlaintextProto,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self::GgswCiphertextProto {
        let ggsw = self
            .core_engine
            .encrypt_scalar_ggsw_ciphertext(
                &secret_key.0,
                &plaintext.0,
                noise,
                decomposition_level_count,
                decomposition_base_log,
            )
            .unwrap();
        ProtoBinaryFourierGgswCiphertext64(self.core_engine.convert_ggsw_ciphertext(&ggsw).unwrap())
    }
}