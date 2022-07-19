use concrete_core::prelude::{FftwStandardGlweRelinearizationKey32, FftwStandardGlweRelinearizationKey64};
use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};

/// A trait implemented by glwe relinearization key prototypes.
pub trait GlweRelinearizationKeyPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit GLWE relinearization key entity.
pub struct ProtoGlweRelinearizationKey32(pub(crate) FftwStandardGlweRelinearizationKey32);
impl GlweRelinearizationKeyPrototype for ProtoGlweRelinearizationKey32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit GLWE relinearization key entity.
pub struct ProtoGlweRelinearizationKey64(pub(crate) FftwStandardGlweRelinearizationKey64);
impl GlweRelinearizationKeyPrototype for ProtoGlweRelinearizationKey64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
