//! Module providing entry points to the `DefaultEngine` implementations of various
//! `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysDiscardingConversionEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Converts an `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64` into an `LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64`. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_u64_view_buffers(
    engine: *mut DefaultEngine,
    input: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    output: *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();
        let output = get_mut_checked(output).unwrap();

        engine
            .discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(output, input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_unchecked_u64_view_buffers(
    engine: *mut DefaultEngine,
    input: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    output: *mut LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysMutView64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut *engine;

        let input = &*input;
        let output = &mut *output;

        engine
            .discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(output, input);
    })
}

/// Raw pointer buffer variant of
/// [`default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    input: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    output: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let input = get_ref_checked(input).unwrap();
        let output = get_mut_checked(output).unwrap();

        let lwe_size = input.input_lwe_dimension().to_lwe_size();
        let glwe_size = input.output_glwe_dimension().to_glwe_size();
        let polynomial_size = input.output_polynomial_size();
        let decomposition_level_count = input.decomposition_level_count();
        let decomposition_base_log = input.decomposition_base_log();
        let key_count = input.key_count();

        let cbs_pfpksks_buffer_length =
            decomposition_level_count.0 * glwe_size.0 * polynomial_size.0 * lwe_size.0 * 
                key_count.0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, cbs_pfpksks_buffer_length);

        let mut output = engine
            .create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from(
                output_as_slice,
                lwe_size,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                key_count,
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();

        engine
            .discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(&mut output, input)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn default_engine_discard_convert_lwe_cbs_pfpksk_to_lwe_cbs_pfpksk_mut_view_unchecked_u64_raw_ptr_buffers(
    engine: *mut DefaultEngine,
    input: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    output: *mut u64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut *engine;

        let input = &*input;
        let output = &mut *output;

        let lwe_size = input.input_lwe_dimension().to_lwe_size();
        let glwe_size = input.output_glwe_dimension().to_glwe_size();
        let polynomial_size = input.output_polynomial_size();
        let decomposition_level_count = input.decomposition_level_count();
        let decomposition_base_log = input.decomposition_base_log();
        let key_count = input.key_count();

        let cbs_pfpksks_buffer_length =
            decomposition_level_count.0 * glwe_size.0 * polynomial_size.0 * lwe_size.0 *
                key_count.0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, cbs_pfpksks_buffer_length);

        let mut output = engine
            .create_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_from_unchecked(
            output_as_slice,
            lwe_size,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            key_count,
        );

        engine
            .discard_convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(&mut output, input);
    })
}
