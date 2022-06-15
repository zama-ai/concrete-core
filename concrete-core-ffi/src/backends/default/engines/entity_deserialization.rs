use crate::buffer::BufferView;
use crate::utils::{
    catch_panic, check_ptr_is_non_null_and_aligned, engine_error_as_readable_string,
    get_mut_checked,
};
use concrete_core::prelude::{
    DefaultSerializationEngine, EntityDeserializationEngine, LweKeyswitchKey64, LweSecretKey64,
};
use std::os::raw::c_int;

/// Deserializes a `LweSecretKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_secret_key_u64(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let secret_key: LweSecretKey64 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(secret_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_secret_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();
        let secret_key: LweSecretKey64 = engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(secret_key));
    })
}

/// Deserializes a `LweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_keyswitch_key_u64(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key: LweKeyswitchKey64 = engine
            .deserialize(buffer.into())
            .or_else(engine_error_as_readable_string)
            .unwrap();

        *result = Box::into_raw(Box::new(keyswitch_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_deserialize_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_deserialize_lwe_keyswitch_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key: LweKeyswitchKey64 = engine.deserialize_unchecked(buffer.into());

        *result = Box::into_raw(Box::new(keyswitch_key));
    })
}
