//! Module providing entry points to the `DefaultEngine` implementations of various
//! `GlweSecretKeyGenerationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Generate a new `GlweSecretKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_glwe_secret_key_u64(
    engine: *mut DefaultEngine,
    dimension: usize,
    poly_size: usize,
    result: *mut *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let heap_allocated_secret_key = Box::new(
            engine
                .generate_new_glwe_secret_key(GlweDimension(dimension), PolynomialSize(poly_size))
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );
        *result = Box::into_raw(heap_allocated_secret_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_generate_new_glwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_glwe_secret_key_unchecked_u64(
    engine: *mut DefaultEngine,
    dimension: usize,
    poly_size: usize,
    result: *mut *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let heap_allocated_secret_key = Box::new(engine.generate_new_glwe_secret_key_unchecked(
            GlweDimension(dimension),
            PolynomialSize(poly_size),
        ));
        *result = Box::into_raw(heap_allocated_secret_key);
    })
}
