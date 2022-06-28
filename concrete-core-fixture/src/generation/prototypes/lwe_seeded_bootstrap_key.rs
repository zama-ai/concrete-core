use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{LweSeededBootstrapKey32, LweSeededBootstrapKey64};

/// A trait implemented by LWE seeded bootstrap key prototypes.
pub trait LweSeededBootstrapKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary to binary LWE seeded bootstrap key entity.
pub struct ProtoBinaryBinaryLweSeededBootstrapKey32(pub(crate) LweSeededBootstrapKey32);
impl LweSeededBootstrapKeyPrototype for ProtoBinaryBinaryLweSeededBootstrapKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary to binary LWE seeded bootstrap key entity.
pub struct ProtoBinaryBinaryLweSeededBootstrapKey64(pub(crate) LweSeededBootstrapKey64);
impl LweSeededBootstrapKeyPrototype for ProtoBinaryBinaryLweSeededBootstrapKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
