use crate::buffer::BufferView;
use crate::utils::{
    catch_panic, check_ptr_is_non_null_and_aligned, engine_error_as_readable_string,
    get_mut_checked,
};
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Deserializes a `LweSecretKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_secret_key_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSecretKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let secret_key: LweSecretKey32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(secret_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_secret_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_secret_key_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSecretKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);
        let secret_key: LweSecretKey32 = engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(secret_key));
    })
}

/// Deserializes a `LweKeyswitchKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_keyswitch_key_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key: LweKeyswitchKey32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(keyswitch_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_keyswitch_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_keyswitch_key_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let keyswitch_key: LweKeyswitchKey32 = engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(keyswitch_key));
    })
}

/// Deserializes a `LweSeededKeyswitchKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_seeded_keyswitch_key_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key: LweSeededKeyswitchKey32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(keyswitch_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_seeded_keyswitch_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_seeded_keyswitch_key_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let seeded_keyswitch_key: LweSeededKeyswitchKey32 =
            engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(seeded_keyswitch_key));
    })
}

/// Deserializes a `LweSeededBootstrapKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSeededBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let seeded_bootstrap_key: LweSeededBootstrapKey32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(seeded_bootstrap_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_seeded_bootstrap_key_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSeededBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let seeded_bootstrap_key: LweSeededBootstrapKey32 =
            engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(seeded_bootstrap_key));
    })
}

/// Deserializes a `LweBootstrapKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_bootstrap_key_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let bootstrap_key: LweBootstrapKey32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(bootstrap_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_bootstrap_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_bootstrap_key_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let seeded_bootstrap_key: LweBootstrapKey32 = engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(seeded_bootstrap_key));
    })
}

/// Deserializes a `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(cbs_pfpksk));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u32`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u32(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = &mut (*engine);

        let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 =
            engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(cbs_pfpksk));
    })
}
