//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextDiscardingAdditionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Add two `LweCiphertextView64` together. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input_1: *const LweCiphertextView64,
    input_2: *const LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input_1 = get_ref_checked(input_1).unwrap();
        let input_2 = get_ref_checked(input_2).unwrap();

        engine
            .discard_add_lwe_ciphertext(output, input_1, input_2)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_add_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    output: *mut LweCiphertextMutView64,
    input_1: *const LweCiphertextView64,
    input_2: *const LweCiphertextView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let output = &mut (*output);
        let input_1 = &(*input_1);
        let input_2 = &(*input_2);

        engine.discard_add_lwe_ciphertext_unchecked(output, input_1, input_2);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_add_lwe_ciphertext_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input_1: *const u64,
    input_2: *const u64,
    lwe_dimension: usize,
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

        let input_1 = get_ref_checked(input_1).unwrap();
        let input_1_as_slice = std::slice::from_raw_parts(input_1, lwe_size);
        let input_1 = engine
            .create_lwe_ciphertext_from(input_1_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input_2 = get_ref_checked(input_2).unwrap();
        let input_2_as_slice = std::slice::from_raw_parts(input_2, lwe_size);
        let input_2 = engine
            .create_lwe_ciphertext_from(input_2_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_add_lwe_ciphertext(&mut output, &input_1, &input_2)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_add_lwe_ciphertext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_add_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    output: *mut u64,
    input_1: *const u64,
    input_2: *const u64,
    lwe_dimension: usize,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_size);
        let mut output = engine.create_lwe_ciphertext_from_unchecked(output_as_slice);

        let input_1_as_slice = std::slice::from_raw_parts(input_1, lwe_size);
        let input_1 = engine.create_lwe_ciphertext_from_unchecked(input_1_as_slice);

        let input_2_as_slice = std::slice::from_raw_parts(input_2, lwe_size);
        let input_2 = engine.create_lwe_ciphertext_from_unchecked(input_2_as_slice);

        engine.discard_add_lwe_ciphertext_unchecked(&mut output, &input_1, &input_2);
    })
}
