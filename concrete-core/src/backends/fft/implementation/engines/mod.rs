//! A module containing the [engines](crate::specification::engines) exposed by the `Concrete-FFT`
//! backend.

mod computation_engine;

pub use computation_engine::{FftEngine, FftError};

mod ggsw_ciphertext_conversion;
mod glwe_ciphertext_ggsw_ciphertext_discarding_external_product;
mod glwe_ciphertexts_ggsw_ciphertext_fusing_cmux;
mod lwe_bootstrap_key_conversion;
mod lwe_ciphertext_discarding_bootstrap;
