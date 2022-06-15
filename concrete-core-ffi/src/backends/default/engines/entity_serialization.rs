use crate::buffer::Buffer;
use crate::utils::{
    catch_panic, check_ptr_is_non_null_and_aligned, engine_error_as_readable_string,
    get_mut_checked, get_ref_checked,
};
use concrete_core::prelude::{
    DefaultSerializationEngine, EntitySerializationEngine, LweKeyswitchKey64, LweSecretKey64,
};
use std::os::raw::c_int;

/// Serializes an `LweSecretKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_secret_key_u64(
    engine: *mut DefaultSerializationEngine,
    secret_key: *const LweSecretKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let secret_key = get_ref_checked(secret_key).unwrap();

        let buffer: Buffer = engine
            .serialize(secret_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_secret_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    secret_key: *const LweSecretKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let secret_key = get_ref_checked(secret_key).unwrap();

        let buffer: Buffer = engine.serialize_unchecked(secret_key).into();

        *result = buffer;
    })
}

/// Serializes a `LweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_keyswitch_key_u64(
    engine: *mut DefaultSerializationEngine,
    keyswitch_key: *const LweKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let buffer: Buffer = engine
            .serialize(keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_keyswitch_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    keyswitch_key: *const LweKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let buffer: Buffer = engine.serialize_unchecked(keyswitch_key).into();

        *result = buffer;
    })
}
