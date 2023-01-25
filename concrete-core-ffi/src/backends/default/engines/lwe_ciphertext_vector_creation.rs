//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextVectorCreationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create an `LweCiphertextVectorView32` from a raw pointer.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_ciphertext_vector_view_from_u32(
    engine: *mut DefaultEngine,
    input: *const u32,
    lwe_size: usize,
    lwe_count: usize,
    result: *mut *mut LweCiphertextVectorView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_container = std::slice::from_raw_parts(input, lwe_size * lwe_count);

        let heap_allocated_lwe_ciphertext_vector_view = Box::new(
            engine
                .create_lwe_ciphertext_vector_from(input_container, LweSize(lwe_size))
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_lwe_ciphertext_vector_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_create_lwe_ciphertext_vector_view_from_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_ciphertext_vector_view_from_unchecked_u32(
    engine: *mut DefaultEngine,
    input: *const u32,
    lwe_size: usize,
    lwe_count: usize,
    result: *mut *mut LweCiphertextVectorView32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_container = std::slice::from_raw_parts(input, lwe_size * lwe_count);

        let heap_allocated_lwe_ciphertext_vector_view = Box::new(
            engine.create_lwe_ciphertext_vector_from_unchecked(input_container, LweSize(lwe_size)),
        );

        *result = Box::into_raw(heap_allocated_lwe_ciphertext_vector_view);
    })
}

/// Create an `LweCiphertextVectorMutView32` from a raw pointer.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_ciphertext_vector_mut_view_from_u32(
    engine: *mut DefaultEngine,
    input: *mut u32,
    lwe_size: usize,
    lwe_count: usize,
    result: *mut *mut LweCiphertextVectorMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_mut_checked(input).unwrap();
        let input_container = std::slice::from_raw_parts_mut(input, lwe_size * lwe_count);

        let heap_allocated_lwe_ciphertext_vector_mut_view = Box::new(
            engine
                .create_lwe_ciphertext_vector_from(input_container, LweSize(lwe_size))
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_lwe_ciphertext_vector_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_create_lwe_ciphertext_vector_mut_view_from_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_ciphertext_vector_mut_view_from_unchecked_u32(
    engine: *mut DefaultEngine,
    input: *mut u32,
    lwe_size: usize,
    lwe_count: usize,
    result: *mut *mut LweCiphertextVectorMutView32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_container = std::slice::from_raw_parts_mut(input, lwe_size * lwe_count);

        let heap_allocated_lwe_ciphertext_vector_mut_view = Box::new(
            engine.create_lwe_ciphertext_vector_from_unchecked(input_container, LweSize(lwe_size)),
        );

        *result = Box::into_raw(heap_allocated_lwe_ciphertext_vector_mut_view);
    })
}
