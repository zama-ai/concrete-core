//! A module containing the [engines](crate::specification::engines) exposed by the default backend.

mod default_engine;
pub use default_engine::*;

#[cfg(feature = "backend_default_parallel")]
mod default_parallel_engine;
pub use default_parallel_engine::*;
