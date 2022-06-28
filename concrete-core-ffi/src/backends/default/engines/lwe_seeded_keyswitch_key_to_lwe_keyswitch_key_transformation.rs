//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Transform an `LweSeededKeyswitchKey64` into a `LweKeyswitchKey64`.
///
/// The passed `LweSeededKeyswitchKey64` is consumed and cannot be accessed afterwards, the passed
/// input pointer is set to NULL by this function.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_u64(
    engine: *mut DefaultEngine,
    lwe_seeded_keyswitch_key: *mut *mut LweSeededKeyswitchKey64,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let lwe_seeded_keyswitch_key_mut_ptr = *get_mut_checked(lwe_seeded_keyswitch_key).unwrap();

        check_ptr_is_non_null_and_aligned(lwe_seeded_keyswitch_key_mut_ptr).unwrap();

        // Recreate the Box
        let heap_allocated_lwe_keyswitch_key = Box::from_raw(lwe_seeded_keyswitch_key_mut_ptr);

        let heap_allocated_keyswitch_key = Box::new(
            engine
                .transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(
                    *heap_allocated_lwe_keyswitch_key,
                )
                .or_else(engine_error_as_readable_string)
                .unwrap(),
        );

        // Now that the key was consumed, signal that by setting the input pointer to null
        *lwe_seeded_keyswitch_key = std::ptr::null_mut();

        *result = Box::into_raw(heap_allocated_keyswitch_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked_u64(
    engine: *mut DefaultEngine,
    lwe_seeded_keyswitch_key: *mut *mut LweSeededKeyswitchKey64,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let lwe_seeded_keyswitch_key_mut_ptr = *lwe_seeded_keyswitch_key;

        // Recreate the Box
        let heap_allocated_lwe_keyswitch_key = Box::from_raw(lwe_seeded_keyswitch_key_mut_ptr);

        let heap_allocated_keyswitch_key = Box::new(
            engine.transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
                *heap_allocated_lwe_keyswitch_key,
            ),
        );

        // Now that the key was consumed, signal that by setting the input pointer to null
        *lwe_seeded_keyswitch_key = std::ptr::null_mut();

        *result = Box::into_raw(heap_allocated_keyswitch_key);
    })
}
