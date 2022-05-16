//! Module providing entry points to the `FftwEngine` implementations of various
//! `LweCiphertextDiscardingBootstrapEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Bootstrap an LWE ciphertext using FFTW. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers(
    engine: *mut FftwEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    accumulator: *const GlweCiphertextView64,
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
/// [`fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u64_view_buffers(
    engine: *mut FftwEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut LweCiphertextMutView64,
    input: *const LweCiphertextView64,
    accumulator: *const GlweCiphertextView64,
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
/// [`fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut u64,
    input: *const u64,
    accumulator: *const u64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = get_mut_checked(fftw_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let input_lwe_size = bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = bootstrap_key.polynomial_size();
        let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut output = default_engine
            .create_lwe_ciphertext(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine
            .create_lwe_ciphertext(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let accumulator = get_ref_checked(accumulator).unwrap();
        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let accumulator = default_engine
            .create_glwe_ciphertext(accumulator_as_slice, polynomial_size)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        fftw_engine
            .discard_bootstrap_lwe_ciphertext(&mut output, &input, &accumulator, bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fftw_engine_lwe_ciphertext_discarding_bootstrap_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn fftw_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u64_raw_ptr_buffers(
    fftw_engine: *mut FftwEngine,
    default_engine: *mut DefaultEngine,
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    output: *mut u64,
    input: *const u64,
    accumulator: *const u64,
) -> c_int {
    catch_panic(|| {
        let fftw_engine = &mut (*fftw_engine);
        let default_engine = &mut (*default_engine);

        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let input_lwe_size = bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = bootstrap_key.polynomial_size();
        let glwe_size = bootstrap_key.glwe_dimension().to_glwe_size();

        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut output = default_engine.create_lwe_ciphertext_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let input = default_engine.create_lwe_ciphertext_unchecked(input_as_slice);

        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let accumulator =
            default_engine.create_glwe_ciphertext_unchecked(accumulator_as_slice, polynomial_size);

        fftw_engine.discard_bootstrap_lwe_ciphertext_unchecked(
            &mut output,
            &input,
            &accumulator,
            bootstrap_key,
        );
    })
}
