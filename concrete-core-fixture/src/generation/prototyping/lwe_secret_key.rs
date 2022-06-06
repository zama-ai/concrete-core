use crate::generation::prototypes::{LweSecretKeyPrototype, ProtoBinaryGlweSecretKey32, ProtoBinaryGlweSecretKey64, ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{LweSecretKeyCreationEngine, LweToGlweSecretKeyTransmutationEngine, PolynomialSize};
use crate::generation::prototyping::PrototypesGlweSecretKey;

/// A trait allowing to manipulate lwe secret key prototypes.
pub trait PrototypesLweSecretKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>
{
    type LweSecretKeyProto: LweSecretKeyPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn new_lwe_secret_key(&mut self, lwe_dimension: LweDimension) -> Self::LweSecretKeyProto;
    // Due to issues with cyclic imports, transmutation of an LWE secret key to a GLWE secret key
    // is available in glwe_secret_keys.rs as part of the PrototypesGlweSecretKey trait
}

impl PrototypesLweSecretKey<Precision32, BinaryKeyDistribution> for Maker {
    type LweSecretKeyProto = ProtoBinaryLweSecretKey32;

    fn new_lwe_secret_key(&mut self, lwe_dimension: LweDimension) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey32(
            self.default_engine
                .create_lwe_secret_key(lwe_dimension)
                .unwrap(),
        )
    }
}

impl PrototypesLweSecretKey<Precision64, BinaryKeyDistribution> for Maker {
    type LweSecretKeyProto = ProtoBinaryLweSecretKey64;

    fn new_lwe_secret_key(&mut self, lwe_dimension: LweDimension) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey64(
            self.default_engine
                .create_lwe_secret_key(lwe_dimension)
                .unwrap(),
        )
    }
}
/// A trait allowing to transmute LWE secret key prototypes.
pub trait TransmutesLweSecretKeyPrototype<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>: PrototypesLweSecretKey<Precision, KeyDistribution> + PrototypesGlweSecretKey<Precision, 
KeyDistribution>
{
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto;
}

impl TransmutesLweSecretKeyPrototype<Precision32, BinaryKeyDistribution> for Maker {
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey32(
            self.default_engine
                .transmute_lwe_secret_key_to_glwe_secret_key(lwe_key.0.to_owned(), polynomial_size)
                .unwrap(),
        )
    }
}

impl TransmutesLweSecretKeyPrototype<Precision64, BinaryKeyDistribution> for Maker {
    fn transmute_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey64(
            self.default_engine
                .transmute_lwe_secret_key_to_glwe_secret_key(lwe_key.0.to_owned(), polynomial_size)
                .unwrap(),
        )
    }
}
