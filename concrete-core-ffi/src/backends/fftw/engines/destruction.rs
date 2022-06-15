//! Module providing entry points to the `FftwEngine` implementations of various `DestructionEngine`
//! traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy an `FftwFourierLweBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_destroy_fftw_fourier_lwe_bootstrap_key_u64(
    engine: *mut FftwEngine,
    bootstrap_key: *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut bootstrap_key = Box::from_raw(bootstrap_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(bootstrap_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_destroy_fftw_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_destroy_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
    engine: *mut FftwEngine,
    bootstrap_key: *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut bootstrap_key = Box::from_raw(bootstrap_key);

        engine.destroy_unchecked(bootstrap_key.as_mut());
    })
}
