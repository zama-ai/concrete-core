//! Module providing entry points to the `CudaEngine` implementations of various
//! `DestructionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy an `CudaLweCiphertext64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_lwe_ciphertext_u64(
    engine: *mut CudaEngine,
    cuda_lwe_ciphertext: *mut CudaLweCiphertext64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(cuda_lwe_ciphertext).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_ciphertext = Box::from_raw(cuda_lwe_ciphertext);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(cuda_lwe_ciphertext.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_destroy_lwe_ciphertext_u64`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_lwe_ciphertext_unchecked_u64(
    engine: *mut CudaEngine,
    cuda_lwe_ciphertext: *mut CudaLweCiphertext64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_ciphertext = Box::from_raw(cuda_lwe_ciphertext);

        engine.destroy_unchecked(cuda_lwe_ciphertext.as_mut());
    })
}

/// Destroy an `CudaFourierLweBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_cuda_lwe_fourier_bootstrap_key_u64(
    engine: *mut CudaEngine,
    cuda_lwe_fourier_bootstrap_key: *mut CudaFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(cuda_lwe_fourier_bootstrap_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_fourier_bootstrap_key = Box::from_raw(cuda_lwe_fourier_bootstrap_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(cuda_lwe_fourier_bootstrap_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_destroy_cuda_lwe_fourier_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_cuda_lwe_fourier_bootstrap_key_unchecked_u64(
    engine: *mut CudaEngine,
    cuda_lwe_fourier_bootstrap_key: *mut CudaFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_fourier_bootstrap_key = Box::from_raw(cuda_lwe_fourier_bootstrap_key);

        engine.destroy_unchecked(cuda_lwe_fourier_bootstrap_key.as_mut());
    })
}

/// Destroy an `CudaLweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_cuda_lwe_keyswitch_key_u64(
    engine: *mut CudaEngine,
    cuda_lwe_keyswitch_key: *mut CudaLweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(cuda_lwe_keyswitch_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_keyswitch_key = Box::from_raw(cuda_lwe_keyswitch_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(cuda_lwe_keyswitch_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_destroy_cuda_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_destroy_cuda_lwe_keyswitch_key_unchecked_u64(
    engine: *mut CudaEngine,
    cuda_lwe_keyswitch_key: *mut CudaLweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut cuda_lwe_keyswitch_key = Box::from_raw(cuda_lwe_keyswitch_key);

        engine.destroy_unchecked(cuda_lwe_keyswitch_key.as_mut());
    })
}
