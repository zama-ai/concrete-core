//! Module providing entry points to the `FftwEngine` implementations of various
//! `LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Perform the circuit bootstrap and the vertical packing with the provided look-up tables. View
/// buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_view_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut LweCiphertextVectorMutView64,
    input: *const LweCiphertextVectorView64,
    luts: *const u64,
    lut_length: usize,
    cbs_level_count: usize,
    cbs_base_log: usize,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = get_mut_checked(fftw_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let luts = get_ref_checked(luts).unwrap();
        let luts = std::slice::from_raw_parts(luts, lut_length);
        let luts = default_engine
            .create_plaintext_vector_from(luts)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let cbs_level_count = DecompositionLevelCount(cbs_level_count);
        let cbs_base_log = DecompositionBaseLog(cbs_base_log);

        let cbs_pfpksk = get_ref_checked(cbs_pfpksk).unwrap();

        fftw_engine
            .discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
                output,
                input,
                bootstrap_key,
                &luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_unchecked_u64_view_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut LweCiphertextVectorMutView64,
    input: *const LweCiphertextVectorView64,
    luts: *const u64,
    lut_length: usize,
    cbs_level_count: usize,
    cbs_base_log: usize,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = &mut (*fftw_engine);
        let default_engine = &mut (*default_engine);

        let output = &mut (*output);
        let input = &(*input);

        let bootstrap_key = &(*bootstrap_key);

        let luts = &(*luts);
        let luts = std::slice::from_raw_parts(luts, lut_length);
        let luts = default_engine.create_plaintext_vector_from_unchecked(luts);

        let cbs_level_count = DecompositionLevelCount(cbs_level_count);
        let cbs_base_log = DecompositionBaseLog(cbs_base_log);

        let cbs_pfpksk = &(*cbs_pfpksk);

        fftw_engine
            .discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
                output,
                input,
                bootstrap_key,
                &luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
            );
    })
}

/// Raw pointer buffer variant of
/// [`fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut u64,
    output_lwe_size: usize,
    output_ciphertext_count: usize,
    input: *const u64,
    input_lwe_size: usize,
    input_ciphertext_count: usize,
    luts: *const u64,
    luts_length: usize,
    cbs_level_count: usize,
    cbs_base_log: usize,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = get_mut_checked(fftw_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let input_lwe_size = LweSize(input_lwe_size);
        let output_lwe_size = LweSize(output_lwe_size);

        let output = get_mut_checked(output).unwrap();
        let output_as_slice =
            std::slice::from_raw_parts_mut(output, output_lwe_size.0 * output_ciphertext_count);
        let mut output = default_engine
            .create_lwe_ciphertext_vector_from(output_as_slice, output_lwe_size)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice =
            std::slice::from_raw_parts(input, input_lwe_size.0 * input_ciphertext_count);
        let input = default_engine
            .create_lwe_ciphertext_vector_from(input_as_slice, input_lwe_size)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let luts = get_ref_checked(luts).unwrap();
        let luts = std::slice::from_raw_parts(luts, luts_length);
        let luts = default_engine
            .create_plaintext_vector_from(luts)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let cbs_level_count = DecompositionLevelCount(cbs_level_count);
        let cbs_base_log = DecompositionBaseLog(cbs_base_log);

        let cbs_pfpksk = get_ref_checked(cbs_pfpksk).unwrap();

        fftw_engine
            .discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
                &mut output,
                &input,
                bootstrap_key,
                &luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing_unchecked_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut u64,
    output_lwe_size: usize,
    output_ciphertext_count: usize,
    input: *const u64,
    input_lwe_size: usize,
    input_ciphertext_count: usize,
    luts: *const u64,
    luts_length: usize,
    cbs_level_count: usize,
    cbs_base_log: usize,
    cbs_pfpksk: *const LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = &mut (*fftw_engine);
        let default_engine = &mut (*default_engine);

        let bootstrap_key = &(*bootstrap_key);

        let input_lwe_size = LweSize(input_lwe_size);
        let output_lwe_size = LweSize(output_lwe_size);

        let output = &mut (*output);
        let output_as_slice =
            std::slice::from_raw_parts_mut(output, output_lwe_size.0 * output_ciphertext_count);
        let mut output = default_engine
            .create_lwe_ciphertext_vector_from_unchecked(output_as_slice, output_lwe_size);

        let input = &(*input);
        let input_as_slice =
            std::slice::from_raw_parts(input, input_lwe_size.0 * input_ciphertext_count);
        let input = default_engine
            .create_lwe_ciphertext_vector_from_unchecked(input_as_slice, input_lwe_size);

        let luts = &(*luts);
        let luts = std::slice::from_raw_parts(luts, luts_length);
        let luts = default_engine.create_plaintext_vector_from_unchecked(luts);

        let cbs_level_count = DecompositionLevelCount(cbs_level_count);
        let cbs_base_log = DecompositionBaseLog(cbs_base_log);

        let cbs_pfpksk = &(*cbs_pfpksk);

        fftw_engine
            .discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
                &mut output,
                &input,
                bootstrap_key,
                &luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
            );
    })
}
