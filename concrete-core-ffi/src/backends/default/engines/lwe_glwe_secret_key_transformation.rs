//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweToGlweSecretKeyTransformationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Transform an `LweSecretKey64` into a `GlweSecretKey64`.
///
/// The passed `LweSecretKey64` is consumed and cannot be accessed afterwards, the passed input
/// pointer is set to NULL by this function.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_transform_lwe_secret_key_to_glwe_secret_key_u64(
    engine: *mut DefaultEngine,
    lwe_secret_key: *mut *mut LweSecretKey64,
    polynomial_size: usize,
    result: *mut *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let lwe_secret_key_mut_ptr = *get_mut_checked(lwe_secret_key).unwrap();

        check_ptr_is_non_null_and_aligned(lwe_secret_key_mut_ptr).unwrap();

        // Recreate the Box
        let heap_allocated_lwe_secret_key = Box::from_raw(lwe_secret_key_mut_ptr);

        let polynomial_size = PolynomialSize(polynomial_size);

        let heap_allocated_glwe_secret_key = Box::new(
            engine
                .transform_lwe_secret_key_to_glwe_secret_key(
                    *heap_allocated_lwe_secret_key,
                    polynomial_size,
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        // Now that the key was consumed, signal that by setting the input pointer to null
        *lwe_secret_key = std::ptr::null_mut();

        *result = Box::into_raw(heap_allocated_glwe_secret_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_transform_lwe_secret_key_to_glwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_transform_lwe_secret_key_to_glwe_secret_key_unchecked_u64(
    engine: *mut DefaultEngine,
    lwe_secret_key: *mut *mut LweSecretKey64,
    polynomial_size: usize,
    result: *mut *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let lwe_secret_key_mut_ptr = *lwe_secret_key;
        // Recreate the Box
        let heap_allocated_lwe_secret_key = Box::from_raw(lwe_secret_key_mut_ptr);

        let polynomial_size = PolynomialSize(polynomial_size);

        let heap_allocated_glwe_secret_key = Box::new(
            engine.transform_lwe_secret_key_to_glwe_secret_key_unchecked(
                *heap_allocated_lwe_secret_key,
                polynomial_size,
            ),
        );

        // Now that the key was consumed, signal that by setting the input pointer to null
        *lwe_secret_key = std::ptr::null_mut();

        *result = Box::into_raw(heap_allocated_glwe_secret_key);
    })
}
