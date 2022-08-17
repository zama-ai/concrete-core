use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{GlweSeededCiphertextVector32, GlweSeededCiphertextVector64};

/// A trait implemented by GLWE seeded ciphertext vector prototypes.
pub trait GlweSeededCiphertextVectorPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GLWE seeded ciphertext vector entity.
pub struct ProtoBinaryGlweSeededCiphertextVector32(pub(crate) GlweSeededCiphertextVector32);
impl GlweSeededCiphertextVectorPrototype for ProtoBinaryGlweSeededCiphertextVector32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GLWE seeded ciphertext vector entity.
pub struct ProtoBinaryGlweSeededCiphertextVector64(pub(crate) GlweSeededCiphertextVector64);
impl GlweSeededCiphertextVectorPrototype for ProtoBinaryGlweSeededCiphertextVector64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
