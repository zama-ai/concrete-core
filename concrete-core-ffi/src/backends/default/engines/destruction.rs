//! Module providing entry points to the `DefaultEngine` implementations of various
//! `DestructionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy a `GlweCiphertextView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_ciphertext_view_u64(
    engine: *mut DefaultEngine,
    glwe_ciphertext_view: *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_view).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_ciphertext_view = Box::from_raw(glwe_ciphertext_view);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(glwe_ciphertext_view.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_glwe_ciphertext_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_ciphertext_view_unchecked_u64(
    engine: *mut DefaultEngine,
    glwe_ciphertext_view: *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_ciphertext_view = Box::from_raw(glwe_ciphertext_view);

        engine.destroy_unchecked(glwe_ciphertext_view.as_mut());
    })
}

/// Destroy a `GlweCiphertextMutView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_ciphertext_mut_view_u64(
    engine: *mut DefaultEngine,
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_mut_view).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_ciphertext_mut_view = Box::from_raw(glwe_ciphertext_mut_view);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(glwe_ciphertext_mut_view.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_glwe_ciphertext_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_ciphertext_mut_view_unchecked_u64(
    engine: *mut DefaultEngine,
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_ciphertext_mut_view = Box::from_raw(glwe_ciphertext_mut_view);

        engine.destroy_unchecked(glwe_ciphertext_mut_view.as_mut());
    })
}

/// Destroy an `LweCiphertextView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_ciphertext_view_u64(
    engine: *mut DefaultEngine,
    lwe_ciphertext_view: *mut LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_view).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_ciphertext_view = Box::from_raw(lwe_ciphertext_view);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(lwe_ciphertext_view.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_ciphertext_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_ciphertext_view_unchecked_u64(
    engine: *mut DefaultEngine,
    lwe_ciphertext_view: *mut LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_ciphertext_view = Box::from_raw(lwe_ciphertext_view);

        engine.destroy_unchecked(lwe_ciphertext_view.as_mut());
    })
}

/// Destroy an `LweCiphertextMutView64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_ciphertext_mut_view_u64(
    engine: *mut DefaultEngine,
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_mut_view).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_ciphertext_mut_view = Box::from_raw(lwe_ciphertext_mut_view);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(lwe_ciphertext_mut_view.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_ciphertext_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_ciphertext_mut_view_unchecked_u64(
    engine: *mut DefaultEngine,
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_ciphertext_mut_view = Box::from_raw(lwe_ciphertext_mut_view);

        engine.destroy_unchecked(lwe_ciphertext_mut_view.as_mut());
    })
}

/// Destroy an `LweSecretKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_secret_key_u64(
    engine: *mut DefaultEngine,
    lwe_secret_key: *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_secret_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_secret_key = Box::from_raw(lwe_secret_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(lwe_secret_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_secret_key_unchecked_u64(
    engine: *mut DefaultEngine,
    lwe_secret_key: *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut lwe_secret_key = Box::from_raw(lwe_secret_key);

        engine.destroy_unchecked(lwe_secret_key.as_mut());
    })
}

/// Destroy a `GlweSecretKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_secret_key_u64(
    engine: *mut DefaultEngine,
    glwe_secret_key: *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_secret_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_secret_key = Box::from_raw(glwe_secret_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(glwe_secret_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_glwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_glwe_secret_key_unchecked_u64(
    engine: *mut DefaultEngine,
    glwe_secret_key: *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut glwe_secret_key = Box::from_raw(glwe_secret_key);

        engine.destroy_unchecked(glwe_secret_key.as_mut());
    })
}

/// Destroy an `LweKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_keyswitch_key_u64(
    engine: *mut DefaultEngine,
    keyswitch_key: *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(keyswitch_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut keyswitch_key = Box::from_raw(keyswitch_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(keyswitch_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_keyswitch_key_unchecked_u64(
    engine: *mut DefaultEngine,
    keyswitch_key: *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut keyswitch_key = Box::from_raw(keyswitch_key);

        engine.destroy_unchecked(keyswitch_key.as_mut());
    })
}

/// Destroy an `LweSeededKeyswitchKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_seeded_keyswitch_key_u64(
    engine: *mut DefaultEngine,
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_keyswitch_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut seeded_keyswitch_key = Box::from_raw(seeded_keyswitch_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(seeded_keyswitch_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_seeded_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_seeded_keyswitch_key_unchecked_u64(
    engine: *mut DefaultEngine,
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut seeded_keyswitch_key = Box::from_raw(seeded_keyswitch_key);

        engine.destroy_unchecked(seeded_keyswitch_key.as_mut());
    })
}

/// Destroy an `LweBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_bootstrap_key_u64(
    engine: *mut DefaultEngine,
    bootstrap_key: *mut LweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut bootstrap_key = Box::from_raw(bootstrap_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(bootstrap_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_bootstrap_key_unchecked_u64(
    engine: *mut DefaultEngine,
    bootstrap_key: *mut LweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut bootstrap_key = Box::from_raw(bootstrap_key);

        engine.destroy_unchecked(bootstrap_key.as_mut());
    })
}

/// Destroy an `LweSeededBootstrapKey64`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_seeded_bootstrap_key_u64(
    engine: *mut DefaultEngine,
    seeded_bootstrap_key: *mut LweSeededBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_bootstrap_key).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut seeded_bootstrap_key = Box::from_raw(seeded_bootstrap_key);

        // Here we use the unchecked version to process the memory of the underlying boxed object
        // Otherwise we may be moving out of the box through a clone and the original memory may not
        // be properly zeroed out.
        engine.destroy_unchecked(seeded_bootstrap_key.as_mut());
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_destroy_lwe_seeded_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_destroy_lwe_seeded_bootstrap_key_unchecked_u64(
    engine: *mut DefaultEngine,
    seeded_bootstrap_key: *mut LweSeededBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        let mut seeded_bootstrap_key = Box::from_raw(seeded_bootstrap_key);

        engine.destroy_unchecked(seeded_bootstrap_key.as_mut());
    })
}
