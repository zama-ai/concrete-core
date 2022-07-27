//! Module providing entry points to the `CudaEngine` implementations of various
//! `LweKeyswitchKeyConversionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Convert an `LweKeyswitchKey64` to an `CudaLweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn
cuda_engine_convert_lwe_keyswitch_key_to_cuda_lwe_keyswitch_key_u64(
    engine: *mut CudaEngine,
    input: *const LweKeyswitchKey64,
    result: *mut *mut CudaLweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();

        let heap_allocated_ksk = Box::new(
            engine
                .convert_lwe_keyswitch_key(input)
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_ksk);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_convert_lwe_keyswitch_key_to_cuda_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn
cuda_engine_convert_lwe_keyswitch_key_to_cuda_lwe_keyswitch_key_unchecked_u64(
    engine: *mut CudaEngine,
    input: *const LweKeyswitchKey64,
    result: *mut *mut CudaLweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input = &(*input);

        let heap_allocated_ksk = Box::new(engine.convert_lwe_keyswitch_key_unchecked(input));

        *result = Box::into_raw(heap_allocated_ksk);
    })
}

/// Convert an `CudaLweKeyswitchKey64` to an `LweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn
cuda_engine_convert_cuda_lwe_keyswitch_key_to_lwe_keyswitch_key_u64(
    engine: *mut CudaEngine,
    input: *const CudaLweKeyswitchKey64,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();

        let heap_allocated_ksk = Box::new(
            engine
                .convert_lwe_keyswitch_key(input)
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_ksk);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_convert_cuda_lwe_keyswitch_key_to_lwe_keyswitch_key_unchecked_u64`]
#[no_mangle]
pub unsafe extern "C" fn
cuda_engine_convert_cuda_lwe_keyswitch_key_to_lwe_keyswitch_key_unchecked_u64(
    engine: *mut CudaEngine,
    input: *const CudaLweKeyswitchKey64,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input = &(*input);

        let heap_allocated_ksk = Box::new(engine.convert_lwe_keyswitch_key_unchecked(input));

        *result = Box::into_raw(heap_allocated_ksk);
    })
}