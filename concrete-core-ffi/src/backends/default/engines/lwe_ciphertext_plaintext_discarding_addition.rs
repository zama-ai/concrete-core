//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextPlaintextDiscardingAdditionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Add a plaintext to an `LweCiphertextView64` into an `LweCiphertextMutView64`. View buffer
/// variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_plaintext_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    adder: u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        let adder = engine
            .create_plaintext_from(&adder)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_add_lwe_ciphertext_plaintext(output, input, &adder)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_add_lwe_ciphertext_plaintext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_plaintext_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    adder: u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let output = &mut (*output);
        let input = &(*input);

        let adder = engine.create_plaintext_from_unchecked(&adder);

        engine.discard_add_lwe_ciphertext_plaintext_unchecked(output, input, &adder);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_add_lwe_ciphertext_plaintext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_plaintext_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input: *const u64,
    lwe_dimension: usize,
    adder: u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine
            .create_lwe_ciphertext_from(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine
            .create_lwe_ciphertext_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let adder = engine
            .create_plaintext_from(&adder)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_add_lwe_ciphertext_plaintext(&mut output, &input, &adder)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_add_lwe_ciphertext_plaintext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_plaintext_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input: *const u64,
    lwe_dimension: usize,
    adder: u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine.create_lwe_ciphertext_from_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine.create_lwe_ciphertext_from_unchecked(input_as_slice);

        let adder = engine.create_plaintext_from_unchecked(&adder);

        engine.discard_add_lwe_ciphertext_plaintext_unchecked(&mut output, &input, &adder);
    })
}
