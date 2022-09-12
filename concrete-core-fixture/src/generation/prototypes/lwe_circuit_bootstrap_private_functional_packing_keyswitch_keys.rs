use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
};

/// A trait implemented by prototypes of private functional packing keyswitch keys array used in
/// circuit bootstrapping.
pub trait LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary private functional packing keyswitch keys
/// array entity used in circuit bootstrapping.
pub struct ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(
    pub(crate) LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
);
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysPrototype
    for ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary private functional packing keyswitch keys
/// array entity used in circuit bootstrapping.
pub struct ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
    pub(crate) LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
);
impl LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysPrototype
    for ProtoBinaryBinaryLweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
{
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
