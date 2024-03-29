//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextDiscardingEncryptionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Encrypt an input `u64` plaintext into an `LweCiphertextMutView64`. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    output: *mut LweCiphertextMutView64,
    input: u64,
    noise: f64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let secret_key = get_ref_checked(secret_key).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = engine
            .create_plaintext_from(&input)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_encrypt_lwe_ciphertext(secret_key, output, &input, Variance(noise))
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    output: *mut LweCiphertextMutView64,
    input: u64,
    noise: f64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let secret_key = &(*secret_key);

        let output = &mut (*output);
        let input = engine.create_plaintext_from_unchecked(&input);

        engine.discard_encrypt_lwe_ciphertext_unchecked(
            secret_key,
            output,
            &input,
            Variance(noise),
        );
    })
}

/// Raw pointer buffer variant of [`default_engine_discard_encrypt_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    output: *mut u64,
    input: u64,
    noise: f64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let secret_key = get_ref_checked(secret_key).unwrap();

        let lwe_size = secret_key.lwe_dimension().to_lwe_size().0;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine
            .create_lwe_ciphertext_from(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = engine
            .create_plaintext_from(&input)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_encrypt_lwe_ciphertext(secret_key, &mut output, &input, Variance(noise))
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_encrypt_lwe_ciphertext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_encrypt_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    secret_key: *const LweSecretKey64,
    output: *mut u64,
    input: u64,
    noise: f64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let secret_key = &(*secret_key);

        let lwe_size = secret_key.lwe_dimension().to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine.create_lwe_ciphertext_from_unchecked(output_as_slice);

        let input = engine.create_plaintext_from_unchecked(&input);

        engine.discard_encrypt_lwe_ciphertext_unchecked(
            secret_key,
            &mut output,
            &input,
            Variance(noise),
        );
    })
}
