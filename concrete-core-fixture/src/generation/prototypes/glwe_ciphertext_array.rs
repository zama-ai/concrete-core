use crate::generation::{
    BinaryKeyDistribution, IntegerPrecision, KeyDistributionMarker, Precision32, Precision64,
};
use concrete_core::prelude::{GlweCiphertextArray32, GlweCiphertextArray64};

/// A trait implemented by glwe ciphertext array prototypes.
pub trait GlweCiphertextArrayPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary glwe ciphertext array entity.
pub struct ProtoBinaryGlweCiphertextArray32(pub(crate) GlweCiphertextArray32);
impl GlweCiphertextArrayPrototype for ProtoBinaryGlweCiphertextArray32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary glwe ciphertext array entity.
pub struct ProtoBinaryGlweCiphertextArray64(pub(crate) GlweCiphertextArray64);
impl GlweCiphertextArrayPrototype for ProtoBinaryGlweCiphertextArray64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
