use crate::buffer::Buffer;
use crate::utils::{
    catch_panic, check_ptr_is_non_null_and_aligned, engine_error_as_readable_string,
    get_mut_checked, get_ref_checked,
};
use concrete_core::prelude::*;
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
        let engine = &mut (*engine);
        let secret_key = &(*secret_key);

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
        let engine = &mut (*engine);
        let keyswitch_key = &(*keyswitch_key);

        let buffer: Buffer = engine.serialize_unchecked(keyswitch_key).into();

        *result = buffer;
    })
}

/// Serializes a `LweSeededKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_seeded_keyswitch_key_u64(
    engine: *mut DefaultSerializationEngine,
    seeded_keyswitch_key: *const LweSeededKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let seeded_keyswitch_key = get_ref_checked(seeded_keyswitch_key).unwrap();

        let buffer: Buffer = engine
            .serialize(seeded_keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_seeded_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_seeded_keyswitch_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    seeded_keyswitch_key: *const LweSeededKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);
        let seeded_keyswitch_key = &(*seeded_keyswitch_key);

        let buffer: Buffer = engine.serialize_unchecked(seeded_keyswitch_key).into();

        *result = buffer;
    })
}

/// Serializes a `LweSeededBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_seeded_bootstrap_key_u64(
    engine: *mut DefaultSerializationEngine,
    seeded_bootstrap_key: *const LweSeededBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        let seeded_bootstrap_key = get_ref_checked(seeded_bootstrap_key).unwrap();

        let buffer: Buffer = engine
            .serialize(seeded_bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_seeded_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_seeded_bootstrap_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    seeded_bootstrap_key: *const LweSeededBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let seeded_bootstrap_key = &(*seeded_bootstrap_key);

        let buffer: Buffer = engine.serialize_unchecked(seeded_bootstrap_key).into();

        *result = buffer;
    })
}

/// Serializes a `LweBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_bootstrap_key_u64(
    engine: *mut DefaultSerializationEngine,
    bootstrap_key: *const LweBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let buffer: Buffer = engine
            .serialize(bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_bootstrap_key_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    bootstrap_key: *const LweBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let bootstrap_key = &(*bootstrap_key);

        let buffer: Buffer = engine.serialize_unchecked(bootstrap_key).into();

        *result = buffer;
    })
}

/// Serializes a `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64(
    engine: *mut DefaultSerializationEngine,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        let cbs_pfpksk = get_ref_checked(cbs_pfpksk).unwrap();

        let buffer: Buffer = engine
            .serialize(cbs_pfpksk)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_serialization_engine_serialize_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u64(
    engine: *mut DefaultSerializationEngine,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let cbs_pfpksk = &(*cbs_pfpksk);

        let buffer: Buffer = engine.serialize_unchecked(cbs_pfpksk).into();

        *result = buffer;
    })
}
