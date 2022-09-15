//! A crate that builds a representation of `concrete-core` sources for automatic api generation.
//!
//! This crate contains the tools to build a _Concrete-Core Representation_ (abreviated `ccr` in the
//! code) from the sources of `concrete-core`. That is, a tree that builds on top of the `syn` ast,
//! to better represents `concrete-core` sources. This representation then makes it simple to
//! generate an api that binds to `concrete-core`.
//!
//! # A note on vocabulary
//!
//! We use the following names in the representation node names:
//!     + engine trait = An `*Engine` trait. In the specification.
//!     + engine trait impl = An `impl *Engine for *` block. In a backend
//!     + engine type = A type that implement some `*Engine` traits. In a backend.
//!     + engine type definition = A `pub struct *Engine{...}` definition of a type that implements
//!       `*Engine` traits. In a backend.
//!     + entity trait = An `*Entity` trait. In the specification.
//!     + entity trait impl = An `impl *Entity for *` block. In a backend
//!     + entity type = A type that implement an `*Entity` traits. In a backend.
//!     + entity type definition = A `pub struct *{...}` definition of a type that implements an
//!       `*Entity` trait. In a backend.

mod ccr;
pub use ccr::*;

mod cfg_eval;
pub use cfg_eval::*;

mod naming;
pub use naming::*;

mod misc;
pub use misc::*;
