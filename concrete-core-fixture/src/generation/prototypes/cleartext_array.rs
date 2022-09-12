use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::{CleartextArray32, CleartextArray64};

/// A trait implemented by cleartext array prototypes.
pub trait CleartextArrayPrototype {
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit cleartext array entity.
pub struct ProtoCleartextArray32(pub(crate) CleartextArray32);
impl CleartextArrayPrototype for ProtoCleartextArray32 {
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit cleartext array entity.
pub struct ProtoCleartextArray64(pub(crate) CleartextArray64);
impl CleartextArrayPrototype for ProtoCleartextArray64 {
    type Precision = Precision64;
}
