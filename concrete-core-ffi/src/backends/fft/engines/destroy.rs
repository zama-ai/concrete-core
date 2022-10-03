//! Module providing entry points to drop entities created by the `fft` backend.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy an `FftFourierLweBootstrapKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_fourier_lwe_bootstrap_key_u64(
    bootstrap_key: *mut FftFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_fft_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_fourier_lwe_bootstrap_key_unchecked_u64(
    bootstrap_key: *mut FftFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key));
    })
}
