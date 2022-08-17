use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LweSecretKey32, LweSecretKey64};

/// A trait implemented by lwe secret key prototypes.
pub trait LweSecretKeyPrototype: PartialEq {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary lwe secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryLweSecretKey32(pub(crate) LweSecretKey32);
impl LweSecretKeyPrototype for ProtoBinaryLweSecretKey32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary lwe secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryLweSecretKey64(pub(crate) LweSecretKey64);
impl LweSecretKeyPrototype for ProtoBinaryLweSecretKey64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
