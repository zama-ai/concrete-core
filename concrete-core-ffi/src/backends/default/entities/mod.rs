//! Module providing utilities (like cloning) to the `C` FFI for the `default` backend entities.

pub mod glwe_secret_key;
pub mod lwe_secret_key;

pub use glwe_secret_key::*;
pub use lwe_secret_key::*;
