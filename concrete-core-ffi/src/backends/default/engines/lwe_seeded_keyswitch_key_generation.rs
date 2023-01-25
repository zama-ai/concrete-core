//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweSeededKeyswitchKeyGenerationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Generate a new `LweSeededKeyswitchKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_lwe_seeded_keyswitch_key_u32(
    engine: *mut DefaultEngine,
    input_key: *const LweSecretKey32,
    output_key: *const LweSecretKey32,
    decomp_level_count: usize,
    decomp_base_log: usize,
    noise: f64,
    result: *mut *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let input_key = get_ref_checked(input_key).unwrap();
        let output_key = get_ref_checked(output_key).unwrap();

        let heap_allocated_ks_key = Box::new(
            engine
                .generate_new_lwe_seeded_keyswitch_key(
                    input_key,
                    output_key,
                    DecompositionLevelCount(decomp_level_count),
                    DecompositionBaseLog(decomp_base_log),
                    Variance(noise),
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        *result = Box::into_raw(heap_allocated_ks_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_generate_new_lwe_seeded_keyswitch_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_generate_new_lwe_seeded_keyswitch_key_unchecked_u32(
    engine: *mut DefaultEngine,
    input_key: *const LweSecretKey32,
    output_key: *const LweSecretKey32,
    decomp_level_count: usize,
    decomp_base_log: usize,
    noise: f64,
    result: *mut *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let input_key = &(*input_key);
        let output_key = &(*output_key);

        let heap_allocated_ks_key =
            Box::new(engine.generate_new_lwe_seeded_keyswitch_key_unchecked(
                input_key,
                output_key,
                DecompositionLevelCount(decomp_level_count),
                DecompositionBaseLog(decomp_base_log),
                Variance(noise),
            ));

        *result = Box::into_raw(heap_allocated_ks_key);
    })
}
