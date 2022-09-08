use crate::generation::prototypes::{
    GlweSecretKeyPrototype, ProtoBinaryGlweSecretKey32, ProtoBinaryGlweSecretKey64,
    ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64,
};
use crate::generation::prototyping::PrototypesLweSecretKey;
use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Maker, Precision32, Precision64,
};
use concrete_core::prelude::{
    GlweDimension, GlweSecretKeyGenerationEngine, GlweToLweSecretKeyTransformationEngine,
    LweToGlweSecretKeyTransformationEngine, PolynomialSize,
};

/// A trait allowing to manipulate GLWE secret key prototypes.
pub trait PrototypesGlweSecretKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>: PrototypesLweSecretKey<Precision, KeyDistribution>
{
    type GlweSecretKeyProto: GlweSecretKeyPrototype<
        Precision = Precision,
        KeyDistribution = KeyDistribution,
    >;
    fn new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto;
    // Due to issues with cyclic imports, transformations between LWE and GLWE secret keys are made
    // available here.
    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto;
    fn transform_lwe_secret_key_to_glwe_secret_key(
        &mut self,
        lwe_key: &Self::LweSecretKeyProto,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto;
}

impl PrototypesGlweSecretKey<Precision32, BinaryKeyDistribution> for Maker {
    type GlweSecretKeyProto = ProtoBinaryGlweSecretKey32;

    fn new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey32(
            self.default_engine
                .generate_new_glwe_secret_key(glwe_dimension, polynomial_size)
                .unwrap(),
        )
    }

    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey32(
            self.default_engine
                .transform_glwe_secret_key_to_lwe_secret_key(glwe_key.0.to_owned())
                .unwrap(),
        )
    }

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

impl PrototypesGlweSecretKey<Precision64, BinaryKeyDistribution> for Maker {
    type GlweSecretKeyProto = ProtoBinaryGlweSecretKey64;

    fn new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        ProtoBinaryGlweSecretKey64(
            self.default_engine
                .generate_new_glwe_secret_key(glwe_dimension, polynomial_size)
                .unwrap(),
        )
    }

    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey64(
            self.default_engine
                .transform_glwe_secret_key_to_lwe_secret_key(glwe_key.0.to_owned())
                .unwrap(),
        )
    }

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
