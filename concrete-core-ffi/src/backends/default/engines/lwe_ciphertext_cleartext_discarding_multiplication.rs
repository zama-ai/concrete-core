//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextCleartextDiscardingMultiplicationEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Multiply an `LweCiphertextView64` with a cleartext. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_mul_lwe_ciphertext_cleartext_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    multiplier: u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        let multiplier: Cleartext64 = engine
            .create_cleartext(&multiplier)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_mul_lwe_ciphertext_cleartext(output, input, &multiplier)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_mul_lwe_ciphertext_cleartext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_mul_lwe_ciphertext_cleartext_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    multiplier: u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let output = &mut (*output);
        let input = &(*input);

        let multiplier: Cleartext64 = engine.create_cleartext_unchecked(&multiplier);

        engine.discard_mul_lwe_ciphertext_cleartext_unchecked(output, input, &multiplier);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_mul_lwe_ciphertext_cleartext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_mul_lwe_ciphertext_cleartext_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input: *const u64,
    lwe_dimension: usize,
    multiplier: u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine
            .create_lwe_ciphertext(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine
            .create_lwe_ciphertext(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let multiplier: Cleartext64 = engine
            .create_cleartext(&multiplier)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_mul_lwe_ciphertext_cleartext(&mut output, &input, &multiplier)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_mul_lwe_ciphertext_cleartext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_mul_lwe_ciphertext_cleartext_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input: *const u64,
    lwe_dimension: usize,
    multiplier: u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine.create_lwe_ciphertext_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, lwe_size);
        let input = engine.create_lwe_ciphertext_unchecked(input_as_slice);

        let multiplier: Cleartext64 = engine.create_cleartext_unchecked(&multiplier);

        engine.discard_mul_lwe_ciphertext_cleartext_unchecked(&mut output, &input, &multiplier);
    })
}
