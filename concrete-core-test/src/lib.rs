#![deny(rustdoc::broken_intra_doc_links)]
//! A module containing backends correctness tests.
//!
//! Each submodule here is expected to be activated by a given feature flag (matching the
//! `backend_*` naming), and to contain the instantiation of a generic correctness test for every
//! implemented operator.
use concrete_core_fixture::{Repetitions, SampleSize};

/// The number of time a test is repeated for a single set of parameter.
// pub const REPETITIONS: Repetitions = Repetitions(10);
// pub const REPETITIONS: Repetitions = Repetitions(10);
pub const REPETITIONS: Repetitions = Repetitions(1);

/// The size of the sample used to perform statistical tests.
pub const SAMPLE_SIZE: SampleSize = SampleSize(100);

#[cfg(feature = "backend_cuda")]
pub mod cuda;
#[cfg(all(test, feature = "backend_default"))]
pub mod default;
#[cfg(all(test, feature = "backend_fft"))]
pub mod fft;
#[cfg(all(test, feature = "backend_ntt"))]
pub mod ntt;
