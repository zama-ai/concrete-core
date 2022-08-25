use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{
    LwePrivateFunctionalPackingKeyswitchKey32, LwePrivateFunctionalPackingKeyswitchKey64,
};

/// A trait implemented by private functional packing keyswitch key prototypes.
pub trait LwePrivateFunctionalPackingKeyswitchKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary private functional packing keyswitch key
/// entity.
pub struct ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey32(
    pub(crate) LwePrivateFunctionalPackingKeyswitchKey32,
);
impl LwePrivateFunctionalPackingKeyswitchKeyPrototype
    for ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey32
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary private functional packing keyswitch key
/// entity.
pub struct ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey64(
    pub(crate) LwePrivateFunctionalPackingKeyswitchKey64,
);
impl LwePrivateFunctionalPackingKeyswitchKeyPrototype
    for ProtoBinaryBinaryLwePrivateFunctionalPackingKeyswitchKey64
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
