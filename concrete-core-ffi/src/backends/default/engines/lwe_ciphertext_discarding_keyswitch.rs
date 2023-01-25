//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCiphertextDiscardingKeyswitchEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Keyswitch an `LweCiphertextView32` into an `LweCiphertextMutView32`. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_keyswitch_lwe_ciphertext_u32_view_buffers(
    engine: *mut DefaultEngine,
    keyswitch_key: *const LweKeyswitchKey32,
    output: *mut LweCiphertextMutView32,
    input: *const LweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        engine
            .discard_keyswitch_lwe_ciphertext(output, input, keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_keyswitch_lwe_ciphertext_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_keyswitch_lwe_ciphertext_unchecked_u32_view_buffers(
    engine: *mut DefaultEngine,
    keyswitch_key: *const LweKeyswitchKey32,
    output: *mut LweCiphertextMutView32,
    input: *const LweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let keyswitch_key = &(*keyswitch_key);

        let output = &mut (*output);
        let input = &(*input);

        engine.discard_keyswitch_lwe_ciphertext_unchecked(output, input, keyswitch_key);
    })
}

/// Raw pointer variant of [`default_engine_discard_keyswitch_lwe_ciphertext_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_keyswitch_lwe_ciphertext_u32_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    keyswitch_key: *const LweKeyswitchKey32,
    output: *mut u32,
    input: *const u32,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let lwe_input_size = keyswitch_key.input_lwe_dimension().to_lwe_size().0;
        let lwe_output_size = keyswitch_key.output_lwe_dimension().to_lwe_size().0;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_output_size);
        let mut output = engine
            .create_lwe_ciphertext_from(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, lwe_input_size);
        let input = engine
            .create_lwe_ciphertext_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_keyswitch_lwe_ciphertext(&mut output, &input, keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_keyswitch_lwe_ciphertext_u32_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_keyswitch_lwe_ciphertext_unchecked_u32_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    keyswitch_key: *const LweKeyswitchKey32,
    output: *mut u32,
    input: *const u32,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let keyswitch_key = &(*keyswitch_key);

        let lwe_input_size = keyswitch_key.input_lwe_dimension().to_lwe_size().0;
        let lwe_output_size = keyswitch_key.output_lwe_dimension().to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_output_size);
        let mut output = engine.create_lwe_ciphertext_from_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, lwe_input_size);
        let input = engine.create_lwe_ciphertext_from_unchecked(input_as_slice);

        engine.discard_keyswitch_lwe_ciphertext_unchecked(&mut output, &input, keyswitch_key);
    })
}
