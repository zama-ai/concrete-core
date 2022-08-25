//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweBootstrapKeyCreationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create an `LweBootstrapKeyMutView64` from a raw pointer.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_bootstrap_key_mut_view_from_u64(
    engine: *mut DefaultEngine,
    input: *mut u64,
    lwe_dimension: usize,
    glwe_size: usize,
    poly_size: usize,
    decomposition_base_log: usize,
    decomposition_level_count: usize,
    result: *mut *mut LweBootstrapKeyMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input = get_mut_checked(input).unwrap();

        let container_length =
            lwe_dimension * glwe_size * glwe_size * poly_size * decomposition_level_count;
        let input_container = std::slice::from_raw_parts_mut(input, container_length);

        let heap_allocated_lwe_bootstrap_key_mut_view = Box::new(
            engine
                .create_lwe_bootstrap_key_from(
                    input_container,
                    GlweSize(glwe_size),
                    PolynomialSize(poly_size),
                    DecompositionBaseLog(decomposition_base_log),
                    DecompositionLevelCount(decomposition_level_count),
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_lwe_bootstrap_key_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_create_lwe_bootstrap_key_mut_view_from_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_create_lwe_bootstrap_key_mut_view_from_unchecked_u64(
    engine: *mut DefaultEngine,
    input: *mut u64,
    lwe_dimension: usize,
    glwe_size: usize,
    poly_size: usize,
    decomposition_base_log: usize,
    decomposition_level_count: usize,
    result: *mut *mut LweBootstrapKeyMutView64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut *engine;

        let input = &mut *input;

        let container_length =
            lwe_dimension * glwe_size * glwe_size * poly_size * decomposition_level_count;
        let input_container = std::slice::from_raw_parts_mut(input, container_length);

        let heap_allocated_lwe_bootstrap_key_mut_view =
            Box::new(engine.create_lwe_bootstrap_key_from_unchecked(
                input_container,
                GlweSize(glwe_size),
                PolynomialSize(poly_size),
                DecompositionBaseLog(decomposition_base_log),
                DecompositionLevelCount(decomposition_level_count),
            ));

        *result = Box::into_raw(heap_allocated_lwe_bootstrap_key_mut_view);
    })
}
