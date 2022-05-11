use crate::generation::prototypes::{
    LweSecretKeyPrototype, ProtoBinaryLweSecretKey32, ProtoBinaryLweSecretKey64,
};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::parameters::LweDimension;
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::LweSecretKeyCreationEngine;

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
