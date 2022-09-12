use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::{PlaintextArray32, PlaintextArray64};

/// A trait implemented by plaintext array prototypes.
pub trait PlaintextArrayPrototype {
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit plaintext array entity.
pub struct ProtoPlaintextArray32(pub(crate) PlaintextArray32);
impl PlaintextArrayPrototype for ProtoPlaintextArray32 {
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit plaintext array entity.
pub struct ProtoPlaintextArray64(pub(crate) PlaintextArray64);
impl PlaintextArrayPrototype for ProtoPlaintextArray64 {
    type Precision = Precision64;
}
