//! Module providing entry points to the `DefaultEngine` implementations of various
//! `GlweCiphertextCreationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create a `GlweCiphertextView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_glwe_ciphertext_view_u64(
    engine: *mut DefaultEngine,
    input: *const u64,
    input_buffer_size: usize,
    polynomial_size: usize,
    result: *mut *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let polynomial_size = PolynomialSize(polynomial_size);

        let input = get_ref_checked(input).unwrap();
        let input_container = std::slice::from_raw_parts(input, input_buffer_size);

        let heap_allocated_glwe_ciphertext_view = Box::new(
            engine
                .create_glwe_ciphertext(input_container, polynomial_size)
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_glwe_ciphertext_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_create_glwe_ciphertext_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_glwe_ciphertext_view_unchecked_u64(
    engine: *mut DefaultEngine,
    input: *const u64,
    glwe_size: usize,
    polynomial_size: usize,
    result: *mut *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_container = std::slice::from_raw_parts(input, glwe_size);

        let polynomial_size = PolynomialSize(polynomial_size);

        let heap_allocated_glwe_ciphertext_view =
            Box::new(engine.create_glwe_ciphertext_unchecked(input_container, polynomial_size));

        *result = Box::into_raw(heap_allocated_glwe_ciphertext_view);
    })
}

/// Create a `GlweCiphertextMutView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_glwe_ciphertext_mut_view_u64(
    engine: *mut DefaultEngine,
    input: *mut u64,
    glwe_size: usize,
    polynomial_size: usize,
    result: *mut *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_mut_checked(input).unwrap();
        let input_container = std::slice::from_raw_parts_mut(input, glwe_size);

        let polynomial_size = PolynomialSize(polynomial_size);

        let heap_allocated_glwe_ciphertext_mut_view = Box::new(
            engine
                .create_glwe_ciphertext(input_container, polynomial_size)
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_glwe_ciphertext_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_create_glwe_ciphertext_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_glwe_ciphertext_mut_view_unchecked_u64(
    engine: *mut DefaultEngine,
    input: *mut u64,
    glwe_size: usize,
    polynomial_size: usize,
    result: *mut *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_container = std::slice::from_raw_parts_mut(input, glwe_size);

        let polynomial_size = PolynomialSize(polynomial_size);

        let heap_allocated_glwe_ciphertext_mut_view =
            Box::new(engine.create_glwe_ciphertext_unchecked(input_container, polynomial_size));

        *result = Box::into_raw(heap_allocated_glwe_ciphertext_mut_view);
    })
}
