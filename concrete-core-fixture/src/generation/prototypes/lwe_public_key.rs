use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LwePublicKey32, LwePublicKey64};

/// A trait implemented by lwe public key prototypes.
pub trait LwePublicKeyPrototype: PartialEq {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary lwe public key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryLwePublicKey32(pub(crate) LwePublicKey32);
impl LwePublicKeyPrototype for ProtoBinaryLwePublicKey32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary lwe public key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryLwePublicKey64(pub(crate) LwePublicKey64);
impl LwePublicKeyPrototype for ProtoBinaryLwePublicKey64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
