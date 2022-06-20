use crate::generation::prototypes::{
    GlweSecretKeyPrototype, ProtoBinaryGlweSecretKey32, ProtoBinaryGlweSecretKey64,
    ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64, ProtoTensorProductGlweSecretKey32,
    ProtoTensorProductGlweSecretKey64,
};
use crate::generation::prototyping::PrototypesLweSecretKey;
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::markers::{
    BinaryKeyDistribution, KeyDistributionMarker, TensorProductKeyDistribution,
};
use concrete_core::prelude::{GlweSecretKeyCreationEngine, GlweToLweSecretKeyTransmutationEngine};

/// A trait allowing to manipulate GLWE secret key prototypes.
pub trait PrototypesGlweSecretKey<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>
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
                .create_glwe_secret_key(glwe_dimension, polynomial_size)
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
                .create_glwe_secret_key(glwe_dimension, polynomial_size)
                .unwrap(),
        )
    }
}

impl PrototypesGlweSecretKey<Precision32, TensorProductKeyDistribution> for Maker {
    type GlweSecretKeyProto = ProtoTensorProductGlweSecretKey32;

    fn new_glwe_secret_key(
        &mut self,
        _glwe_dimension: GlweDimension,
        _polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        unimplemented!()
    }
}

impl PrototypesGlweSecretKey<Precision64, TensorProductKeyDistribution> for Maker {
    type GlweSecretKeyProto = ProtoTensorProductGlweSecretKey64;

    fn new_glwe_secret_key(
        &mut self,
        _glwe_dimension: GlweDimension,
        _polynomial_size: PolynomialSize,
    ) -> Self::GlweSecretKeyProto {
        unimplemented!()
    }
}

/// A trait allowing to transmute GLWE secret key prototypes to LWE secret key prototypes.
pub trait TransmutesGlweToLweSecretKeyPrototype<
    Precision: IntegerPrecision,
    KeyDistribution: KeyDistributionMarker,
>:
    PrototypesGlweSecretKey<Precision, KeyDistribution>
    + PrototypesLweSecretKey<Precision, KeyDistribution>
{
    fn transmute_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto;
}

impl TransmutesGlweToLweSecretKeyPrototype<Precision32, BinaryKeyDistribution> for Maker {
    fn transmute_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey32(
            self.default_engine
                .transmute_glwe_secret_key_to_lwe_secret_key(glwe_key.0.to_owned())
                .unwrap(),
        )
    }
}

impl TransmutesGlweToLweSecretKeyPrototype<Precision64, BinaryKeyDistribution> for Maker {
    fn transmute_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_key: &Self::GlweSecretKeyProto,
    ) -> Self::LweSecretKeyProto {
        ProtoBinaryLweSecretKey64(
            self.default_engine
                .transmute_glwe_secret_key_to_lwe_secret_key(glwe_key.0.to_owned())
                .unwrap(),
        )
    }
}
