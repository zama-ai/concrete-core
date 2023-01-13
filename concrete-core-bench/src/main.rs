#![deny(rustdoc::broken_intra_doc_links)]
//! A module containing backends benchmarking facilities.
//!
//! Each `backend_*` submodule here is expected to be activated by a given feature flag
//! (matching the module name), and to contain the instantiation of a generic benchmarking
//! for every implemented operator.

pub mod benchmark;

#[cfg(feature = "backend_default")]
mod default;

#[cfg(any(feature = "backend_fft", feature = "backend_fft_parallel"))]
mod fft;

#[cfg(feature = "backend_cuda")]
mod cuda;

// The main entry point. Uses criterion as benchmark harness.
fn main() {
    // We instantiate the benchmarks for different backends depending on the feature flag activated.
    #[cfg(feature = "backend_default")]
    default::bench();
    #[cfg(all(feature = "backend_default", feature = "backend_default_parallel"))]
    default::bench_parallel();
    #[cfg(feature = "backend_fft")]
    fft::bench();
    #[cfg(feature = "backend_fft_parallel")]
    fft::bench_parallel();
    #[cfg(feature = "backend_cuda")]
    cuda::bench();
    #[cfg(feature = "backend_cuda")]
    cuda::bench_amortized();
    #[cfg(feature = "backend_cuda")]
    cuda::bench_cuda_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_64(
    );
    #[cfg(feature = "backend_cuda")]
    cuda::bench_cuda_lwe_ciphertext_vector_discarding_wop_pbs_64();

    // We launch the benchmarks.
    criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
}
