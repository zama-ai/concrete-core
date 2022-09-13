use crate::generation::prototypes::{
    LwePublicKeyPrototype, ProtoBinaryLwePublicKey32, ProtoBinaryLwePublicKey64,
};
use crate::generation::prototyping::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    LwePublicKeyGenerationEngine, LwePublicKeyZeroEncryptionCount, Variance,
};

/// A trait allowing to manipulate lwe secret key prototypes.
pub trait PrototypesLwePublicKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>: PrototypesLweSecretKey<Precision, KeyDistribution>
{
    type LwePublicKeyProto: LwePublicKeyPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn generate_new_lwe_public_key(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        count: LwePublicKeyZeroEncryptionCount,
        noise: Variance,
    ) -> Self::LwePublicKeyProto;
}

impl PrototypesLwePublicKey<Precision32, BinaryKeyDistribution> for Maker {
    type LwePublicKeyProto = ProtoBinaryLwePublicKey32;

    fn generate_new_lwe_public_key(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        count: LwePublicKeyZeroEncryptionCount,
        noise: Variance,
    ) -> Self::LwePublicKeyProto {
        ProtoBinaryLwePublicKey32(
            self.default_parallel_engine
                .generate_new_lwe_public_key(&secret_key.0, noise, count)
                .unwrap(),
        )
    }
}

impl PrototypesLwePublicKey<Precision64, BinaryKeyDistribution> for Maker {
    type LwePublicKeyProto = ProtoBinaryLwePublicKey64;

    fn generate_new_lwe_public_key(
        &mut self,
        secret_key: &Self::LweSecretKeyProto,
        count: LwePublicKeyZeroEncryptionCount,
        noise: Variance,
    ) -> Self::LwePublicKeyProto {
        ProtoBinaryLwePublicKey64(
            self.default_parallel_engine
                .generate_new_lwe_public_key(&secret_key.0, noise, count)
                .unwrap(),
        )
    }
}
