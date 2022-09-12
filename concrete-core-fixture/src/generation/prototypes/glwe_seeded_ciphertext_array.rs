use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{GlweSeededCiphertextArray32, GlweSeededCiphertextArray64};

/// A trait implemented by GLWE seeded ciphertext array prototypes.
pub trait GlweSeededCiphertextArrayPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GLWE seeded ciphertext array entity.
pub struct ProtoBinaryGlweSeededCiphertextArray32(pub(crate) GlweSeededCiphertextArray32);
impl GlweSeededCiphertextArrayPrototype for ProtoBinaryGlweSeededCiphertextArray32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GLWE seeded ciphertext array entity.
pub struct ProtoBinaryGlweSeededCiphertextArray64(pub(crate) GlweSeededCiphertextArray64);
impl GlweSeededCiphertextArrayPrototype for ProtoBinaryGlweSeededCiphertextArray64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
