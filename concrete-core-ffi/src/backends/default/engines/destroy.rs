//! Module providing entry points to drop the entities created by the `default` backend.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Destroy a `GlweCiphertextView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_view_u32(
    glwe_ciphertext_view: *mut GlweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_ciphertext_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_ciphertext_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_view_unchecked_u32(
    glwe_ciphertext_view: *mut GlweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_ciphertext_view));
    })
}

/// Destroy a `GlweCiphertextMutView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_mut_view_u32(
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_ciphertext_mut_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_ciphertext_mut_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_ciphertext_mut_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_ciphertext_mut_view_unchecked_u32(
    glwe_ciphertext_mut_view: *mut GlweCiphertextMutView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_ciphertext_mut_view));
    })
}

/// Destroy an `LweCiphertextView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_view_u32(
    lwe_ciphertext_view: *mut LweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_view_unchecked_u32(
    lwe_ciphertext_view: *mut LweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_view));
    })
}

/// Destroy an `LweCiphertextMutView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_mut_view_u32(
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_mut_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_mut_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_mut_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_mut_view_unchecked_u32(
    lwe_ciphertext_mut_view: *mut LweCiphertextMutView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_mut_view));
    })
}

/// Destroy an `LweCiphertextVectorView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_vector_view_u32(
    lwe_ciphertext_vector_view: *mut LweCiphertextVectorView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_vector_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_vector_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_vector_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_vector_view_unchecked_u32(
    lwe_ciphertext_vector_view: *mut LweCiphertextVectorView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_vector_view));
    })
}

/// Destroy an `LweCiphertextVectorMutView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_vector_mut_view_u32(
    lwe_ciphertext_vector_mut_view: *mut LweCiphertextVectorMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_ciphertext_vector_mut_view).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_vector_mut_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_ciphertext_vector_mut_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_ciphertext_vector_mut_view_unchecked_u32(
    lwe_ciphertext_vector_mut_view: *mut LweCiphertextVectorMutView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_ciphertext_vector_mut_view));
    })
}

/// Destroy an `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u32(
    cbs_pfpksk: *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(cbs_pfpksk).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(cbs_pfpksk));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked_u32(
    cbs_pfpksk: *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(cbs_pfpksk));
    })
}

/// Destroy an `LweSecretKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_secret_key_u32(lwe_secret_key: *mut LweSecretKey32) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(lwe_secret_key).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_secret_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_secret_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_secret_key_unchecked_u32(
    lwe_secret_key: *mut LweSecretKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(lwe_secret_key));
    })
}

/// Destroy a `GlweSecretKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_secret_key_u32(
    glwe_secret_key: *mut GlweSecretKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(glwe_secret_key).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_secret_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_glwe_secret_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_glwe_secret_key_unchecked_u32(
    glwe_secret_key: *mut GlweSecretKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(glwe_secret_key));
    })
}

/// Destroy an `LweKeyswitchKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_u32(
    keyswitch_key: *mut LweKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(keyswitch_key).unwrap();
        // Reconstruct the box and drop it
        drop(Box::from_raw(keyswitch_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_keyswitch_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_unchecked_u32(
    keyswitch_key: *mut LweKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(keyswitch_key));
    })
}

/// Destroy an `LweKeyswitchKeyMutView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_mut_view_u32(
    keyswitch_key_mut_view: *mut LweKeyswitchKeyMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(keyswitch_key_mut_view).unwrap();
        // Reconstruct the box and drop it
        drop(Box::from_raw(keyswitch_key_mut_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_keyswitch_key_mut_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_keyswitch_key_mut_view_unchecked_u32(
    keyswitch_key_mut_view: *mut LweKeyswitchKeyMutView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(keyswitch_key_mut_view));
    })
}

/// Destroy an `LweSeededKeyswitchKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_keyswitch_key_u32(
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_keyswitch_key).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(seeded_keyswitch_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_seeded_keyswitch_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_keyswitch_key_unchecked_u32(
    seeded_keyswitch_key: *mut LweSeededKeyswitchKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(seeded_keyswitch_key));
    })
}

/// Destroy an `LweBootstrapKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_u32(
    bootstrap_key: *mut LweBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key).unwrap();
        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_bootstrap_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_unchecked_u32(
    bootstrap_key: *mut LweBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key));
    })
}

/// Destroy an `LweBootstrapKeyMutView32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_mut_view_u32(
    bootstrap_key_mut_view: *mut LweBootstrapKeyMutView32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(bootstrap_key_mut_view).unwrap();
        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key_mut_view));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_bootstrap_key_mut_view_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_bootstrap_key_mut_view_unchecked_u32(
    bootstrap_key_mut_view: *mut LweBootstrapKeyMutView32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(bootstrap_key_mut_view));
    })
}

/// Destroy an `LweSeededBootstrapKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_bootstrap_key_u32(
    seeded_bootstrap_key: *mut LweSeededBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeded_bootstrap_key).unwrap();
        // Reconstruct the box and drop it
        drop(Box::from_raw(seeded_bootstrap_key));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_lwe_seeded_bootstrap_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn destroy_lwe_seeded_bootstrap_key_unchecked_u32(
    seeded_bootstrap_key: *mut LweSeededBootstrapKey32,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(seeded_bootstrap_key));
    })
}
