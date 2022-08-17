use crate::generation::prototypes::{
    LweSecretKeyPrototype, ProtoBinaryGlweSecretKey32, ProtoBinaryGlweSecretKey64,
    ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64,
};
use crate::generation::prototyping::PrototypesGlweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::{
    LweSecretKeyCreationEngine, LweToGlweSecretKeyTransformationEngine, PolynomialSize,
};

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
/// A trait allowing to transform LWE secret key prototypes to GLWE secret key prototypes.
pub trait TransformsLweToGlweSecretKeyPrototype<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesLweSecretKey<Precision, KeyDistribution>
    + PrototypesGlweSecretKey<Precision, KeyDistribution>
{
    fn transform_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto;
}

impl TransformsLweToGlweSecretKeyPrototype<Precision32, BinaryKeyDistribution> for Maker {
    fn transform_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey32(
            self.default_engine
                .transform_lwe_secret_key_to_glwe_secret_key(lwe_key.0.to_owned(), polynomial_size)
                .unwrap(),
        )
    }
}

impl TransformsLweToGlweSecretKeyPrototype<Precision64, BinaryKeyDistribution> for Maker {
    fn transform_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey64(
            self.default_engine
                .transform_lwe_secret_key_to_glwe_secret_key(lwe_key.0.to_owned(), polynomial_size)
                .unwrap(),
        )
    }
}
