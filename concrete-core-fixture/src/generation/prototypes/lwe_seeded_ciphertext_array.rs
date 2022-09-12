use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LweSeededCiphertextArray32, LweSeededCiphertextArray64};

/// A trait implemented by LWE seeded ciphertext prototypes.
pub trait LweSeededCiphertextArrayPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary LWE seeded ciphertext array entity.
pub struct ProtoBinaryLweSeededCiphertextArray32(pub(crate) LweSeededCiphertextArray32);
impl LweSeededCiphertextArrayPrototype for ProtoBinaryLweSeededCiphertextArray32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary LWE seeded ciphertext array entity.
pub struct ProtoBinaryLweSeededCiphertextArray64(pub(crate) LweSeededCiphertextArray64);
impl LweSeededCiphertextArrayPrototype for ProtoBinaryLweSeededCiphertextArray64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
