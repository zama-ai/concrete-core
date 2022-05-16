//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextDecryptionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Decrypt an `LweCiphertextView64`. The plaintext is also retrieved as a `u64` directly. View
/// buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_decrypt_lwe_ciphertext_u64_view_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    input: *const LweCiphertextView64,
    result: *mut u64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        let secret_key = get_ref_checked(secret_key).unwrap();

        let input = get_ref_checked(input).unwrap();

        let decrypted_plaintext = engine
            .decrypt_lwe_ciphertext(secret_key, input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
        *result = engine
            .retrieve_plaintext(&decrypted_plaintext)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_decrypt_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_decrypt_lwe_ciphertext_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    input: *const LweCiphertextView64,
    result: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let secret_key = &(*secret_key);

        let input = &(*input);

        let decrypted_plaintext = engine.decrypt_lwe_ciphertext_unchecked(secret_key, input);
        *result = engine.retrieve_plaintext_unchecked(&decrypted_plaintext);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_decrypt_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_decrypt_lwe_ciphertext_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    input: *const u64,
    result: *mut u64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();

        let secret_key = get_ref_checked(secret_key).unwrap();

        let lwe_size = secret_key.lwe_dimension().to_lwe_size().0;

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine
            .create_lwe_ciphertext(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let decrypted_plaintext = engine
            .decrypt_lwe_ciphertext(secret_key, &input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
        *result = engine
            .retrieve_plaintext(&decrypted_plaintext)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_decrypt_lwe_ciphertext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_decrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    input: *const u64,
    result: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let secret_key = &(*secret_key);

        let lwe_size = secret_key.lwe_dimension().to_lwe_size().0;

        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine.create_lwe_ciphertext_unchecked(input_as_slice);

        let decrypted_plaintext = engine.decrypt_lwe_ciphertext_unchecked(secret_key, &input);
        *result = engine.retrieve_plaintext_unchecked(&decrypted_plaintext);
    })
}
