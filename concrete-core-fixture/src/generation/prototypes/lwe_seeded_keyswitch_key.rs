use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LweSeededKeyswitchKey32, LweSeededKeyswitchKey64};

/// A trait implemented by seeded LWE keyswitch key prototypes.
pub trait LweSeededKeyswitchKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary to binary seeded LWE keyswitch key entity.
pub struct ProtoBinaryBinaryLweSeededKeyswitchKey32(pub(crate) LweSeededKeyswitchKey32);
impl LweSeededKeyswitchKeyPrototype for ProtoBinaryBinaryLweSeededKeyswitchKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary to binary seeded LWE keyswitch key entity.
pub struct ProtoBinaryBinaryLweSeededKeyswitchKey64(pub(crate) LweSeededKeyswitchKey64);
impl LweSeededKeyswitchKeyPrototype for ProtoBinaryBinaryLweSeededKeyswitchKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
