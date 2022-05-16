//! Module providing utilities (like cloning and serialization) to the `C` FFI for the `default`
//! backend entities.

pub mod lwe_keyswitch_key;
pub mod lwe_secret_key;

pub use lwe_keyswitch_key::*;
pub use lwe_secret_key::*;
