use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{FftwStandardGlweRelinearizationKey32, FftwStandardGlweRelinearizationKey64};

/// A trait implemented by glwe relinearization key prototypes.
pub trait GlweRelinearizationKeyPrototype {
    type InputKeyDistribution: KeyDistributionMarker;
    type OutputKeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit glwe relinearization key entity.
pub struct ProtoStandardRelinearizationKey32(pub(crate) FftwStandardGlweRelinearizationKey32);
impl GlweRelinearizationKeyPrototype for ProtoStandardRelinearizationKey32 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit glwe relinearization key entity.
pub struct ProtoStandardRelinearizationKey64(pub(crate) FftwStandardGlweRelinearizationKey64);
impl GlweRelinearizationKeyPrototype for ProtoStandardRelinearizationKey64 {
    type InputKeyDistribution = BinaryKeyDistribution;
    type OutputKeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
