//! Module providing entry points to the `FftwEngine` implementations of various
//! `LweCiphertextDiscardingBitExtractEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Extract bits of an LWE ciphertext using FFTW. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_view_buffers(
    engine: *mut FftwEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    keyswitch_key: *const LweKeyswitchKey64,
    output: *mut LweCiphertextArrayMutView64,
    input: *const LweCiphertextView64,
    extracted_bits_count: usize,
    delta_log: usize,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        engine
            .discard_extract_bits_lwe_ciphertext(
                output,
                input,
                bootstrap_key,
                keyswitch_key,
                ExtractedBitsCount(extracted_bits_count),
                DeltaLog(delta_log),
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_view_buffers(
    engine: *mut FftwEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    keyswitch_key: *const LweKeyswitchKey64,
    output: *mut LweCiphertextArrayMutView64,
    input: *const LweCiphertextView64,
    extracted_bits_count: usize,
    delta_log: usize,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let bootstrap_key = &(*bootstrap_key);
        let keyswitch_key = &(*keyswitch_key);

        let output = &mut (*output);
        let input = &(*input);

        engine.discard_extract_bits_lwe_ciphertext_unchecked(
            output,
            input,
            bootstrap_key,
            keyswitch_key,
            ExtractedBitsCount(extracted_bits_count),
            DeltaLog(delta_log),
        );
    })
}

/// Raw pointer buffer variant of
/// [`fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    keyswitch_key: *const LweKeyswitchKey64,
    output: *mut u64,
    input: *const u64,
    extracted_bits_count: usize,
    delta_log: usize,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = get_mut_checked(fftw_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();
        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let input_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;
        let output_lwe_size = keyswitch_key.output_lwe_dimension().to_lwe_size().0;
        let output_lwe_count = extracted_bits_count;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice =
            std::slice::from_raw_parts_mut(output, output_lwe_size * output_lwe_count);
        let mut output = default_engine
            .create_lwe_ciphertext_array_from(output_as_slice, LweSize(output_lwe_size))
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine
            .create_lwe_ciphertext_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        fftw_engine
            .discard_extract_bits_lwe_ciphertext(
                &mut output,
                &input,
                bootstrap_key,
                keyswitch_key,
                ExtractedBitsCount(extracted_bits_count),
                DeltaLog(delta_log),
            )
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_lwe_ciphertext_discarding_bit_extraction_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bit_extraction_unchecked_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    keyswitch_key: *const LweKeyswitchKey64,
    output: *mut u64,
    input: *const u64,
    extracted_bits_count: usize,
    delta_log: usize,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = &mut (*fftw_engine);
        let default_engine = &mut (*default_engine);

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();
        let keyswitch_key = get_ref_checked(keyswitch_key).unwrap();

        let input_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;
        let output_lwe_size = keyswitch_key.output_lwe_dimension().to_lwe_size().0;
        let output_lwe_count = extracted_bits_count;

        let output_as_slice =
            std::slice::from_raw_parts_mut(output, output_lwe_size * output_lwe_count);
        let mut output = default_engine
            .create_lwe_ciphertext_array_from_unchecked(output_as_slice, LweSize(output_lwe_size));

        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine.create_lwe_ciphertext_from_unchecked(input_as_slice);

        fftw_engine.discard_extract_bits_lwe_ciphertext_unchecked(
            &mut output,
            &input,
            bootstrap_key,
            keyswitch_key,
            ExtractedBitsCount(extracted_bits_count),
            DeltaLog(delta_log),
        );
    })
}
