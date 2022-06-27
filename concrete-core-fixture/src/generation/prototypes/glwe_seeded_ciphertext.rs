use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{GlweSeededCiphertext32, GlweSeededCiphertext64};

/// A trait implemented by GlweSeeded ciphertext prototypes.
pub trait GlweSeededCiphertextPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GlweSeeded ciphertext entity.
pub struct ProtoBinaryGlweSeededCiphertext32(pub(crate) GlweSeededCiphertext32);
impl GlweSeededCiphertextPrototype for ProtoBinaryGlweSeededCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GlweSeeded ciphertext entity.
pub struct ProtoBinaryGlweSeededCiphertext64(pub(crate) GlweSeededCiphertext64);
impl GlweSeededCiphertextPrototype for ProtoBinaryGlweSeededCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
