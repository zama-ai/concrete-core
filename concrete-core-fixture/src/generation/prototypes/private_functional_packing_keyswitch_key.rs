use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{
    PrivateFunctionalPackingKeyswitchKey32, PrivateFunctionalPackingKeyswitchKey64,
};

/// A trait implemented by private functional packing keyswitch key prototypes.
pub trait PrivateFunctionalPackingKeyswitchKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary private functional packing keyswitch key
/// entity.
pub struct ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32(
    pub(crate) PrivateFunctionalPackingKeyswitchKey32,
);
impl PrivateFunctionalPackingKeyswitchKeyPrototype
    for ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey32
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary private functional packing keyswitch key
/// entity.
pub struct ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64(
    pub(crate) PrivateFunctionalPackingKeyswitchKey64,
);
impl PrivateFunctionalPackingKeyswitchKeyPrototype
    for ProtoBinaryBinaryPrivateFunctionalPackingKeyswitchKey64
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
