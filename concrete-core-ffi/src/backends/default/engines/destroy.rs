//! Module providing entry points to drop the entities created by the `default` backend.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy a `GlweCiphertextView64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_view_u64(
    glwe_ciphertext_view: *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_view).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_ciphertext_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_ciphertext_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_view_unchecked_u64(
    glwe_ciphertext_view: *mut GlweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_ciphertext_view);
    })
}

/// Destroy a `GlweCiphertextMutView64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_mut_view_u64(
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_mut_view).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_ciphertext_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_ciphertext_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_mut_view_unchecked_u64(
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_ciphertext_mut_view);
    })
}

/// Destroy an `LweCiphertextView64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_view_u64(
    lwe_ciphertext_view: *mut LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_view).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_ciphertext_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_view_unchecked_u64(
    lwe_ciphertext_view: *mut LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_ciphertext_view);
    })
}

/// Destroy an `LweCiphertextMutView64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_mut_view_u64(
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_mut_view).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_ciphertext_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_mut_view_unchecked_u64(
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_ciphertext_mut_view);
    })
}

/// Destroy an `LweSecretKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_secret_key_u64(lwe_secret_key: *mut LweSecretKey64) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_secret_key).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_secret_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_secret_key_unchecked_u64(
    lwe_secret_key: *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(lwe_secret_key);
    })
}

/// Destroy a `GlweSecretKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_secret_key_u64(
    glwe_secret_key: *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_secret_key).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_secret_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_secret_key_unchecked_u64(
    glwe_secret_key: *mut GlweSecretKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(glwe_secret_key);
    })
}

/// Destroy an `LweKeyswitchKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_u64(
    keyswitch_key: *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(keyswitch_key).unwrap();
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(keyswitch_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_unchecked_u64(
    keyswitch_key: *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(keyswitch_key);
    })
}

/// Destroy an `LweSeededKeyswitchKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_keyswitch_key_u64(
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_keyswitch_key).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(seeded_keyswitch_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_seeded_keyswitch_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_keyswitch_key_unchecked_u64(
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(seeded_keyswitch_key);
    })
}

/// Destroy an `LweBootstrapKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_u64(
    bootstrap_key: *mut LweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_unchecked_u64(
    bootstrap_key: *mut LweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key);
    })
}

/// Destroy an `LweBootstrapKeyMutView64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_mut_view_u64(
    bootstrap_key_mut_view: *mut LweBootstrapKeyMutView64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key_mut_view).unwrap();
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key_mut_view);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_bootstrap_key_mut_view_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_mut_view_unchecked_u64(
    bootstrap_key_mut_view: *mut LweBootstrapKeyMutView64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(bootstrap_key_mut_view);
    })
}

/// Destroy an `LweSeededBootstrapKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_bootstrap_key_u64(
    seeded_bootstrap_key: *mut LweSeededBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_bootstrap_key).unwrap();
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(seeded_bootstrap_key);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_seeded_bootstrap_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_bootstrap_key_unchecked_u64(
    seeded_bootstrap_key: *mut LweSeededBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(seeded_bootstrap_key);
    })
}
