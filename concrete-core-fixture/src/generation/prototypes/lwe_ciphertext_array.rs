use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{LweCiphertextArray32, LweCiphertextArray64};

/// A trait implemented by lwe ciphertext array prototypes.
pub trait LweCiphertextArrayPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary lwe ciphertext array entity.
pub struct ProtoBinaryLweCiphertextArray32(pub(crate) LweCiphertextArray32);
impl LweCiphertextArrayPrototype for ProtoBinaryLweCiphertextArray32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

///  type representing the prototype of a 64 bit binary lwe ciphertext array entity.
pub struct ProtoBinaryLweCiphertextArray64(pub(crate) LweCiphertextArray64);
impl LweCiphertextArrayPrototype for ProtoBinaryLweCiphertextArray64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
