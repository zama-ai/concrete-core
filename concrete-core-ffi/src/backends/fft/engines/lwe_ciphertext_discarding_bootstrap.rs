//! Module providing entry points to the `FftEngine` implementations of various
//! `LweCiphertextDiscardingBootstrapEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Bootstrap an LWE ciphertext using FFT. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fft_engine_lwe_ciphertext_discarding_bootstrap_u32_view_buffers(
    engine: *mut FftEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    output: *mut LweCiphertextMutView32,
    input: *const LweCiphertextView32,
    accumulator: *const GlweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let output = get_mut_checked(output).unwrap();
        let input = get_ref_checked(input).unwrap();

        let accumulator = get_ref_checked(accumulator).unwrap();

        engine
            .discard_bootstrap_lwe_ciphertext(output, input, accumulator, bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fft_engine_lwe_ciphertext_discarding_bootstrap_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fft_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u32_view_buffers(
    engine: *mut FftEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    output: *mut LweCiphertextMutView32,
    input: *const LweCiphertextView32,
    accumulator: *const GlweCiphertextView32,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let bootstrap_key = &(*bootstrap_key);

        let output = &mut (*output);
        let input = &(*input);

        let accumulator = &(*accumulator);

        engine.discard_bootstrap_lwe_ciphertext_unchecked(
            output,
            input,
            accumulator,
            bootstrap_key,
        );
    })
}

/// Raw pointer buffer variant of
/// [`fft_engine_lwe_ciphertext_discarding_bootstrap_u32_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fft_engine_lwe_ciphertext_discarding_bootstrap_u32_raw_ptr_buffers(
    fft_engine: *mut FftEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    output: *mut u32,
    input: *const u32,
    accumulator: *const u32,
) -> c_int {
    catch_panic(|| {
        let fft_engine = get_mut_checked(fft_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let input_lwe_size = bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = bootstrap_key.polynomial_size();
        let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut output = default_engine
            .create_lwe_ciphertext_from(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine
            .create_lwe_ciphertext_from(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let accumulator = get_ref_checked(accumulator).unwrap();
        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let accumulator = default_engine
            .create_glwe_ciphertext_from(accumulator_as_slice, polynomial_size)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        fft_engine
            .discard_bootstrap_lwe_ciphertext(&mut output, &input, &accumulator, bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fft_engine_lwe_ciphertext_discarding_bootstrap_u32_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fft_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u32_raw_ptr_buffers(
    fft_engine: *mut FftEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    output: *mut u32,
    input: *const u32,
    accumulator: *const u32,
) -> c_int {
    catch_panic(|| {
        let fft_engine = &mut (*fft_engine);
        let default_engine = &mut (*default_engine);

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let input_lwe_size = bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = bootstrap_key.polynomial_size();
        let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();

        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut output = default_engine.create_lwe_ciphertext_from_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine.create_lwe_ciphertext_from_unchecked(input_as_slice);

        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let accumulator = default_engine
            .create_glwe_ciphertext_from_unchecked(accumulator_as_slice, polynomial_size);

        fft_engine.discard_bootstrap_lwe_ciphertext_unchecked(
            &mut output,
            &input,
            &accumulator,
            bootstrap_key,
        );
    })
}
