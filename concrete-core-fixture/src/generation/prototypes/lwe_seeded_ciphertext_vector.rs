use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};
use concrete_core::prelude::{LweSeededCiphertextVector32, LweSeededCiphertextVector64};

/// A trait implemented by LWE seeded ciphertext prototypes.
pub trait LweSeededCiphertextVectorPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary LWE seeded ciphertext vector entity.
pub struct ProtoBinaryLweSeededCiphertextVector32(pub(crate) LweSeededCiphertextVector32);
impl LweSeededCiphertextVectorPrototype for ProtoBinaryLweSeededCiphertextVector32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary LWE seeded ciphertext vector entity.
pub struct ProtoBinaryLweSeededCiphertextVector64(pub(crate) LweSeededCiphertextVector64);
impl LweSeededCiphertextVectorPrototype for ProtoBinaryLweSeededCiphertextVector64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
