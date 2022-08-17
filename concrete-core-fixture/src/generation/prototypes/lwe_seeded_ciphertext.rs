use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LweSeededCiphertext32, LweSeededCiphertext64};

/// A trait implemented by LWE seeded ciphertext prototypes.
pub trait LweSeededCiphertextPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary LWE seeded ciphertext entity.
pub struct ProtoBinaryLweSeededCiphertext32(pub(crate) LweSeededCiphertext32);
impl LweSeededCiphertextPrototype for ProtoBinaryLweSeededCiphertext32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary LWE seeded ciphertext entity.
pub struct ProtoBinaryLweSeededCiphertext64(pub(crate) LweSeededCiphertext64);
impl LweSeededCiphertextPrototype for ProtoBinaryLweSeededCiphertext64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
