//! Module providing entry points to the `DefaultEngine` implementations of various
//! `GlweCiphertextDiscardingTrivialEncryptionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Trivially encrypt the `input` plaintext vector into a `GlweCiphertextMutView32`. View buffer
/// variant.
///
/// This function creates a temporary copy of the input buffer in a `PlaintextVector32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut GlweCiphertextMutView32,
    input: *const u32,
    polynomial_size: usize,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let output = get_mut_checked(output).unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, polynomial_size);

        let plaintext_vector = engine
            .create_plaintext_vector_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_trivially_encrypt_glwe_ciphertext(output, &plaintext_vector)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_trivially_encrypt_glwe_ciphertext_unchecked_u32_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut GlweCiphertextMutView32,
    input: *const u32,
    polynomial_size: usize,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let output = &mut (*output);

        let input_as_slice = std::slice::from_raw_parts(input, polynomial_size);

        let plaintext_vector = engine.create_plaintext_vector_from_unchecked(input_as_slice);

        engine.discard_trivially_encrypt_glwe_ciphertext_unchecked(output, &plaintext_vector);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u32,
    output_buffer_size: usize,
    input: *const u32,
    polynomial_size: usize,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, output_buffer_size);
        let mut output = engine
            .create_glwe_ciphertext_from(output_as_slice, PolynomialSize(polynomial_size))
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, polynomial_size);

        let plaintext_vector = engine
            .create_plaintext_vector_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_trivially_encrypt_glwe_ciphertext(&mut output, &plaintext_vector)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_trivially_encrypt_glwe_ciphertext_u32_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_trivially_encrypt_glwe_ciphertext_unchecked_u32_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u32,
    output_buffer_size: usize,
    input: *const u32,
    polynomial_size: usize,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let output_as_slice = std::slice::from_raw_parts_mut(output, output_buffer_size);
        let mut output = engine.create_glwe_ciphertext_from_unchecked(
            output_as_slice,
            PolynomialSize(polynomial_size),
        );

        let input_as_slice = std::slice::from_raw_parts(input, polynomial_size);

        let plaintext_vector = engine.create_plaintext_vector_from_unchecked(input_as_slice);

        engine.discard_trivially_encrypt_glwe_ciphertext_unchecked(&mut output, &plaintext_vector);
    })
}
