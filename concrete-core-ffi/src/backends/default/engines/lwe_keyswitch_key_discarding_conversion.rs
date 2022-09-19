//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweKeyswitchKeyDiscardingConversionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Converts an `LweKeyswitchKey64` into an `LweKeyswitchKeyMutView64`. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_view_buffers(
    engine: *mut DefaultEngine,
    input: *const LweKeyswitchKey64,
    output: *mut LweKeyswitchKeyMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();
        let output = get_mut_checked(output).unwrap();

        engine
            .discard_convert_lwe_keyswitch_key(output, input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    input: *const LweKeyswitchKey64,
    output: *mut LweKeyswitchKeyMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut *engine;

        let input = &*input;
        let output = &mut *output;

        engine.discard_convert_lwe_keyswitch_key_unchecked(output, input);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    input: *const LweKeyswitchKey64,
    output: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();
        let output = get_mut_checked(output).unwrap();

        let input_lwe_dimension = input.input_lwe_dimension();
        let output_lwe_dimension = input.output_lwe_dimension();
        let decomposition_level_count = input.decomposition_level_count();
        let decomposition_base_log = input.decomposition_base_log();

        let ksk_buffer_length = input_lwe_dimension.0
            * output_lwe_dimension.to_lwe_size().0
            * decomposition_level_count.0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, ksk_buffer_length);

        let mut output = engine
            .create_lwe_keyswitch_key_from(
                output_as_slice,
                output_lwe_dimension,
                decomposition_base_log,
                decomposition_level_count,
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_convert_lwe_keyswitch_key(&mut output, input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_keyswitch_key_to_lwe_keyswitch_key_mut_view_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    input: *const LweKeyswitchKey64,
    output: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut *engine;

        let input = &*input;
        let output = &mut *output;

        let input_lwe_dimension = input.input_lwe_dimension();
        let output_lwe_dimension = input.output_lwe_dimension();
        let decomposition_level_count = input.decomposition_level_count();
        let decomposition_base_log = input.decomposition_base_log();

        let ksk_buffer_length = input_lwe_dimension.0
            * output_lwe_dimension.to_lwe_size().0
            * decomposition_level_count.0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, ksk_buffer_length);

        let mut output = engine.create_lwe_keyswitch_key_from_unchecked(
            output_as_slice,
            output_lwe_dimension,
            decomposition_base_log,
            decomposition_level_count,
        );

        engine.discard_convert_lwe_keyswitch_key_unchecked(&mut output, input);
    })
}
