//! Module providing entry points to drop entities created by the `fftw` backend.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy an `FftwFourierLweBootstrapKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_fftw_fourier_lwe_bootstrap_key_u64(
    bootstrap_key: *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_fftw_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
    bootstrap_key: *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key);
    })
}
