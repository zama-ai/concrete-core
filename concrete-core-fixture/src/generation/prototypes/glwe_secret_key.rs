use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker, TensorProductKeyDistribution};
use concrete_core::prelude::{GlweSecretKey32, GlweSecretKey64, GlweTensorProductSecretKey32, GlweTensorProductSecretKey64};

/// A trait implemented by GLWE secret key prototypes.
pub trait GlweSecretKeyPrototype: PartialEq {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GLWE secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryGlweSecretKey32(pub(crate) GlweSecretKey32);
impl GlweSecretKeyPrototype for ProtoBinaryGlweSecretKey32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GLWE secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoBinaryGlweSecretKey64(pub(crate) GlweSecretKey64);
impl GlweSecretKeyPrototype for ProtoBinaryGlweSecretKey64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}

/// A type representing the prototype of a 32 bit tensor product GLWE secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoTensorProductGlweSecretKey32(pub(crate) GlweTensorProductSecretKey32);
impl GlweSecretKeyPrototype for ProtoTensorProductGlweSecretKey32 {
    type KeyDistribution = TensorProductKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit tensor product GLWE secret key entity.
#[derive(PartialEq, Eq)]
pub struct ProtoTensorProductGlweSecretKey64(pub(crate) GlweTensorProductSecretKey64);
impl GlweSecretKeyPrototype for ProtoTensorProductGlweSecretKey64 {
    type KeyDistribution = TensorProductKeyDistribution;
    type Precision = Precision64;
}
