#![deny(rustdoc::broken_intra_doc_links)]
// All functions of the API are unsafe, so we explain once in the main doc and don't repeat for each
// function
#![allow(clippy::missing_safety_doc)]

//! Welcome to the `concrete-ffi` documentation!
//!
//! This crate provides an experimental `C` FFI giving the ability to call `concrete-core`
//! primitives from `C` and other languages which are able to call into and link to `C` libraries,
//! thus bringing *Fully Homomorphic Encryption* (FHE) to these languages.
//!
//! # Audience
//!
//! This crate will be of interest to developers who do not primarily write Rust code and who can
//! use their language of choice to interface with `C` code. Using this crate they can create the
//! proper structures and wrappers to call `concrete-core`'s primitives from their language.
//!
//! This crate will also be of interest to compiler writers who may want to compile programs to
//! their FHE equivalents. You can for example lower an IR to `concrete-core` function calls
//! through the wrappers provided in this crate, thus obtaining an equivalent FHE programs in terms
//! of computations. Proper parameterization of the resulting FHE program is required to ensure
//! correctness and adequate security.
//!
//! # Features and conditional compilation
//!
//! This crate reproduces the `concrete-core` features. So enabling a feature on this crate will
//! enable the feature with the same name on `concrete-core`.
//!
//! # Architecture
//!
//! This crate follows the `concrete-core` project structure, the exception being there is no
//! `implementation` or `private` modules in this crate's source tree. You can for example find the
//! creation and destruction entry points for the [`FftwEngine`](backends::fftw::engines) in
//! `backends::fftw::engines` instead of `backends::fftw::implementation::engines`.
//!
//! The [`backends`] module maps to the `concrete-core` backend module and provides wrappers to call
//! a selection of engines from `C`.
//!
//! The [`seeders`] module provides utilities to provide seeders when building engines. It does not
//! expose structures allowing to manipulate the seeders themselves but rather gives the possibility
//! to create a [`SeederBuilder`](seeders::SeederBuilder) than can be passed to the engine creation
//! functions that require it.
//!
//! The [`buffer`] module which provides structures to help with key serialization and
//! deserialization.
//!
//! The [`mem`] module which contains some alignment constants. Though the aligment should be
//! consistent across languages, this ensures there are no surprises when passing pointers across
//! the `C` FFI boundary.
//!
//! The `utils` private module which provides convenience functions for repeatdly used code in the
//! FFI itself.
//!
//! # Naming convention
//!
//! Functions in the FFI are named following this general pattern:
//!
//! `<snake_cased_engine_name>_<engine_function_name>_<data_type>_<additional_information>`
//!
//! Example if you want to use the [`FftwEngine`](backends::fftw::engines) to do a discarding
//! bootstrap on an LWE Ciphertext taking ciphertext views as buffers, you will call:
//!
//! `fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers` you also have the unchecked
//! version available `fftw_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u64_view_buffers`.
//!
//! Note: there are some exceptions for creation engine which can yield Ciphertexts/Views/MutViews
//! or for conversion engines which have the names of the input and output types they convert
//! from/to in their `C` FFI counterpart. Some name mangling/different naming convention is to be
//! expected at some point in later versions of this `C` FFI to disambiguate and for consistency
//! reasons.
//!
//! # Safety, checked and unchecked functions
//!
//! Because this is a `C` FFI all functions are unsafe as they are manipulating raw pointers which
//! have no guarantee of being valid. For specific safety concerns for the different wrappers
//! provided, please refer to the safety information for the specific engine and implementation in
//! the `concrete-core` documentation.
//!
//! Functions come in `checked` and `unchecked` versions:
//!
//! The `checked` version will:
//! - catch panics (panics across an FFI boundary are Undefined Behavior) and print the panic
//!   backtrace
//! - check that every pointer is not null and well aligned
//! - EXCEPT for destroy engines which use unchecked versions (to avoid unboxing objects), use all
//!   the checked versions of the required engines
//! - return 0 if everything went well, 1 otherwise and print the associated error message/panic
//!   backtrace
//!
//! Note that you can get more insights from a panic using the `RUST_BACKTRACE` env variable as you
//! normally would in rust (setting it to `1` or `full`).
//!
//! The `unchecked` version will:
//! - catch panics (panics across an FFI boundary are Undefined Behavior) and print the panic
//!   backtrace
//! - no pointer check is performed, a null pointer or out of bound read/write will likely segfault
//!   or worse
//! - use all the unchecked versions of the required engines
//! - return 0 if everything went well, 1 otherwise and print the associated error message/panic
//!   backtrace
//!
//! We currently propose two "flavours" for the C FFI:
//!
//! - The `view_buffers` indicates that for engines taking input and output ciphertexts, ciphertext
//! views of the proper type (mutable or not) have to be passed to the function for processing. This
//! version benefits from better checking at runtime, the only downside is that it requires
//! additional heap allocations which requires a bit more management from the user (and may be a bit
//! less performant if views are built just-in time as heap allocations are involved).
//!
//! - The `raw_ptr_buffers` indicates that for engines taking input and output ciphertexts, raw
//! pointers of the proper type and pointing to a large enough buffer have to be passed to the
//! function for processing. The required views will be automatically allocated by the FFI on the
//! stack when needed. Additional dimension/size information may be required if it cannot be deduced
//! from context (e.g. from key sizes). It is the responsibility of the caller to allocate buffers
//! with the proper sizes. The buffer cannot be null obviously and cannot alias/overlap, passing
//! buffers that don't respect these constraints exposes you to Undefined Behavior.
//!
//! # Memory management
//!
//! All entities returned by the FFI are heap-allocated through `Box` and therefore require a call
//! to the proper deallocation/destruction function to avoid memory leaks.
//!
//! Pointers passed to the FFI must not alias/overlap each other for a given call to the FFI.

pub mod backends;
#[cfg(feature = "serde_serialize")]
pub mod buffer;
pub mod generators;
pub mod mem;
pub mod seeders;
pub(crate) mod utils;
