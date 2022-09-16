//! Low-overhead homomorphic primitives.
//!
//! This module implements low-overhead fully homomorphic operations.
//!
//! Throughout this module we use two integer-like types: `Scalar` and `NttScalar`. In the context
//! of this module, `NttScalar` is used for the representation of numbers during the NTT. This type
//! should be able to represent q^2, where q is the modulus used for the NTT, in order to support
//! correct multiplication mod q. The type `Scalar` is used as in the other backends.

pub mod bootstrap;
pub mod ggsw;
pub mod glwe;
