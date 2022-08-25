use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LwePackingKeyswitchKey32, LwePackingKeyswitchKey64};

/// A trait implemented by packing keyswitch key prototypes.
pub trait LwePackingKeyswitchKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary to binary packing keyswitch key entity.
pub struct ProtoBinaryBinaryLwePackingKeyswitchKey32(pub(crate) LwePackingKeyswitchKey32);
impl LwePackingKeyswitchKeyPrototype for ProtoBinaryBinaryLwePackingKeyswitchKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary to binary packing keyswitch key entity.
pub struct ProtoBinaryBinaryLwePackingKeyswitchKey64(pub(crate) LwePackingKeyswitchKey64);
impl LwePackingKeyswitchKeyPrototype for ProtoBinaryBinaryLwePackingKeyswitchKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
