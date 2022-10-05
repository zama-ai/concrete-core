//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweSecretKeyGenerationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Generate a new `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
    engine: *mut DefaultEngine,
    input_lwe_key: *const LweSecretKey64,
    output_glwe_key: *const GlweSecretKey64,
    cbs_pfpksk_decomposition_base_log: usize,
    cbs_pfpksk_decomposition_level_count: usize,
    noise: f64,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input_lwe_key = get_ref_checked(input_lwe_key).unwrap();
        let output_glwe_key = get_ref_checked(output_glwe_key).unwrap();

        let heap_allocated_cbs_pfpksk = Box::new(
            engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                    input_lwe_key,
                    output_glwe_key,
                    DecompositionBaseLog(cbs_pfpksk_decomposition_base_log),
                    DecompositionLevelCount(cbs_pfpksk_decomposition_level_count),
                    Variance(noise),
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );
        *result = Box::into_raw(heap_allocated_cbs_pfpksk);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
    engine: *mut DefaultEngine,
    input_lwe_key: *const LweSecretKey64,
    output_glwe_key: *const GlweSecretKey64,
    cbs_pfpksk_decomposition_base_log: usize,
    cbs_pfpksk_decomposition_level_count: usize,
    noise: f64,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_lwe_key = &(*input_lwe_key);
        let output_glwe_key = &(*output_glwe_key);

        let heap_allocated_cbs_pfpksk = Box::new(
            engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                    input_lwe_key,
                    output_glwe_key,
                    DecompositionBaseLog(cbs_pfpksk_decomposition_base_log),
                    DecompositionLevelCount(cbs_pfpksk_decomposition_level_count),
                    Variance(noise),
                )
        );
        *result = Box::into_raw(heap_allocated_cbs_pfpksk);
    })
}

/// Generate a new `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_parallel_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
    engine: *mut DefaultParallelEngine,
    input_lwe_key: *const LweSecretKey64,
    output_glwe_key: *const GlweSecretKey64,
    cbs_pfpksk_decomposition_base_log: usize,
    cbs_pfpksk_decomposition_level_count: usize,
    noise: f64,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input_lwe_key = get_ref_checked(input_lwe_key).unwrap();
        let output_glwe_key = get_ref_checked(output_glwe_key).unwrap();

        let heap_allocated_cbs_pfpksk = Box::new(
            engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                    input_lwe_key,
                    output_glwe_key,
                    DecompositionBaseLog(cbs_pfpksk_decomposition_base_log),
                    DecompositionLevelCount(cbs_pfpksk_decomposition_level_count),
                    Variance(noise),
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );
        *result = Box::into_raw(heap_allocated_cbs_pfpksk);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_parallel_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_parallel_engine_generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
    engine: *mut DefaultParallelEngine,
    input_lwe_key: *const LweSecretKey64,
    output_glwe_key: *const GlweSecretKey64,
    cbs_pfpksk_decomposition_base_log: usize,
    cbs_pfpksk_decomposition_level_count: usize,
    noise: f64,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_lwe_key = &(*input_lwe_key);
        let output_glwe_key = &(*output_glwe_key);

        let heap_allocated_cbs_pfpksk = Box::new(
            engine
                .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
                    input_lwe_key,
                    output_glwe_key,
                    DecompositionBaseLog(cbs_pfpksk_decomposition_base_log),
                    DecompositionLevelCount(cbs_pfpksk_decomposition_level_count),
                    Variance(noise),
                )
        );
        *result = Box::into_raw(heap_allocated_cbs_pfpksk);
    })
}
