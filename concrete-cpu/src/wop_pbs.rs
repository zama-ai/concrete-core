use core::slice;

use concrete_core::backends::fft::private::c64;
use concrete_core::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKey;
use concrete_core::backends::fft::private::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
    extract_bits, extract_bits_scratch,
};
use concrete_core::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
use concrete_core::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use concrete_core::commons::math::polynomial::PolynomialList;
use concrete_core::prelude::*;
use dyn_stack::DynStack;

use crate::{Fft, Parallelism, ScratchStatus};

#[must_use]
#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_extract_bit_lwe_ciphertext_u64_scratch(
    stack_size: *mut usize,
    stack_align: *mut usize,
    // ciphertexts dimensions
    ct_out_dimension: usize,
    ct_out_count: usize,
    ct_in_dimension: usize,
    // bootstrap parameters
    bsk_decomposition_level_count: usize,
    bsk_glwe_dimension: usize,
    bsk_polynomial_size: usize,
    bsk_input_lwe_dimension: usize,
    // keyswitch_parameters
    ksk_decomposition_level_count: usize,
    ksk_input_dimension: usize,
    ksk_output_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
) -> ScratchStatus {
    unused!(
        parallelism,
        bsk_decomposition_level_count,
        bsk_input_lwe_dimension,
        ksk_decomposition_level_count,
        ksk_input_dimension,
        ksk_output_dimension,
        ct_out_count,
    );

    if let Ok(scratch) = extract_bits_scratch::<u64>(
        LweDimension(ct_in_dimension),
        LweDimension(ct_out_dimension),
        GlweDimension(bsk_glwe_dimension).to_glwe_size(),
        PolynomialSize(bsk_polynomial_size),
        unsafe { (*fft).inner.as_view() },
    ) {
        unsafe {
            *stack_size = scratch.size_bytes();
            *stack_align = scratch.align_bytes();
        }
        ScratchStatus::Valid
    } else {
        ScratchStatus::SizeOverflow
    }
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_extract_bit_lwe_ciphertext_u64(
    // ciphertexts
    ct_vec_out: *mut u64,
    ct_in: *const u64,
    // bootstrap key
    fourier_bsk: *const f64,
    // keyswitch key
    ksk: *const u64,
    // ciphertexts dimensions
    ct_out_dimension: usize,
    ct_out_count: usize,
    ct_in_dimension: usize,
    // extract bit parameters
    number_of_bits: usize,
    delta_log: usize,
    // bootstrap parameters
    bsk_decomposition_level_count: usize,
    bsk_decomposition_base_log: usize,
    bsk_glwe_dimension: usize,
    bsk_polynomial_size: usize,
    bsk_input_lwe_dimension: usize,
    // keyswitch_parameters
    ksk_decomposition_level_count: usize,
    ksk_decomposition_base_log: usize,
    ksk_input_dimension: usize,
    ksk_output_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
    stack: *mut u8,
    stack_size: usize,
) {
    unused!(parallelism);

    assert_eq!(ct_in_dimension, bsk_glwe_dimension * bsk_polynomial_size);
    assert_eq!(ct_in_dimension, ksk_input_dimension);
    assert_eq!(ct_out_dimension, ksk_output_dimension);
    assert_eq!(ct_out_count, number_of_bits);
    assert_eq!(ksk_output_dimension, bsk_input_lwe_dimension);
    assert!(64 < number_of_bits + delta_log);

    let ct_out_size = LweDimension(ct_out_dimension).to_lwe_size().0;
    let lwe_list_out = LweList::from_container(
        unsafe { slice::from_raw_parts_mut(ct_vec_out, ct_out_size * ct_out_count) },
        LweSize(ct_out_size),
    );

    let ct_in_size = LweDimension(ct_in_dimension).to_lwe_size().0;
    let lwe_in = LweCiphertext::from_container(unsafe { slice::from_raw_parts(ct_in, ct_in_size) });

    let ksk = LweKeyswitchKey::from_container(
        unsafe {
            slice::from_raw_parts(
                ksk,
                ksk_decomposition_level_count * (ksk_output_dimension + 1) * ksk_input_dimension,
            )
        },
        DecompositionBaseLog(ksk_decomposition_base_log),
        DecompositionLevelCount(ksk_decomposition_level_count),
        LweDimension(ksk_output_dimension),
    );

    let bsk_glwe_size = GlweDimension(bsk_glwe_dimension).to_glwe_size().0;
    let fourier_bsk = FourierLweBootstrapKey::new(
        unsafe {
            slice::from_raw_parts(
                fourier_bsk as *const c64,
                bsk_input_lwe_dimension
                    * (bsk_polynomial_size / 2)
                    * bsk_decomposition_level_count
                    * bsk_glwe_size
                    * bsk_glwe_size,
            )
        },
        LweDimension(bsk_input_lwe_dimension),
        PolynomialSize(bsk_polynomial_size),
        GlweSize(bsk_glwe_size),
        DecompositionBaseLog(bsk_decomposition_base_log),
        DecompositionLevelCount(bsk_decomposition_level_count),
    );

    extract_bits(
        lwe_list_out,
        lwe_in,
        ksk,
        fourier_bsk,
        DeltaLog(delta_log),
        ExtractedBitsCount(number_of_bits),
        unsafe { (*fft).inner.as_view() },
        DynStack::new(unsafe { slice::from_raw_parts_mut(stack as _, stack_size) }),
    );
}

#[must_use]
#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_u64_scratch(
    stack_size: *mut usize,
    stack_align: *mut usize,
    // ciphertext dimensions
    ct_out_dimension: usize,
    ct_out_count: usize,
    ct_in_dimension: usize,
    ct_in_count: usize,
    small_lut_size: usize,
    small_lut_count: usize,
    // bootstrap parameters
    bsk_decomposition_level_count: usize,
    bsk_glwe_dimension: usize,
    bsk_polynomial_size: usize,
    bsk_input_lwe_dimension: usize,
    // keyswitch_parameters
    fpksk_decomposition_level_count: usize,
    fpksk_input_dimension: usize,
    fpksk_output_glwe_dimension: usize,
    fpksk_output_polynomial_size: usize,
    fpksk_count: usize,
    // circuit bootstrap parameters
    cbs_decomposition_level_count: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
) -> ScratchStatus {
    unused!(
        ct_out_dimension,
        small_lut_size,
        bsk_decomposition_level_count,
        bsk_input_lwe_dimension,
        fpksk_decomposition_level_count,
        fpksk_input_dimension,
        fpksk_output_glwe_dimension,
        fpksk_output_polynomial_size,
        fpksk_count,
        parallelism,
    );
    let bsk_output_lwe_dimension = bsk_glwe_dimension * bsk_polynomial_size;

    if let Ok(scratch) = circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
        CiphertextCount(ct_in_count),
        CiphertextCount(ct_out_count),
        LweDimension(ct_in_dimension).to_lwe_size(),
        PolynomialCount(small_lut_count),
        LweDimension(bsk_output_lwe_dimension).to_lwe_size(),
        PolynomialSize(fpksk_output_polynomial_size),
        GlweDimension(bsk_glwe_dimension).to_glwe_size(),
        DecompositionLevelCount(cbs_decomposition_level_count),
        unsafe { (*fft).inner.as_view() },
    ) {
        unsafe {
            *stack_size = scratch.size_bytes();
            *stack_align = scratch.align_bytes();
        }
        ScratchStatus::Valid
    } else {
        ScratchStatus::SizeOverflow
    }
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_u64(
    // ciphertexts
    ct_out_vec: *mut u64,
    ct_in_vec: *const u64,
    // lookup table
    lut: *const u64,
    // bootstrap key
    fourier_bsk: *const f64,
    // packing keyswitch key
    fpksk: *const u64,
    // ciphertext dimensions
    ct_out_dimension: usize,
    ct_out_count: usize,
    ct_in_dimension: usize,
    ct_in_count: usize,
    small_lut_count: usize,
    small_lut_size: usize,
    // bootstrap parameters
    bsk_decomposition_level_count: usize,
    bsk_decomposition_base_log: usize,
    bsk_glwe_dimension: usize,
    bsk_polynomial_size: usize,
    bsk_input_lwe_dimension: usize,
    // keyswitch_parameters
    fpksk_decomposition_level_count: usize,
    fpksk_decomposition_base_log: usize,
    fpksk_input_dimension: usize,
    fpksk_output_glwe_dimension: usize,
    fpksk_output_polynomial_size: usize,
    fpksk_count: usize,
    // circuit bootstrap parameters
    cbs_decomposition_level_count: usize,
    cbs_decomposition_base_log: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
    stack: *mut u8,
    stack_size: usize,
) {
    unused!(parallelism);

    let bsk_output_lwe_dimension = bsk_glwe_dimension * bsk_polynomial_size;
    assert_eq!(bsk_output_lwe_dimension, fpksk_input_dimension);
    assert_eq!(ct_in_dimension, bsk_input_lwe_dimension);
    assert_eq!(
        ct_out_dimension,
        fpksk_output_glwe_dimension * fpksk_output_polynomial_size
    );
    assert_eq!(small_lut_size, fpksk_output_polynomial_size);
    assert!(small_lut_size >= fpksk_output_polynomial_size);
    assert_ne!(cbs_decomposition_base_log, 0);
    assert_ne!(cbs_decomposition_level_count, 0);
    assert!(cbs_decomposition_level_count * cbs_decomposition_base_log <= 64);

    let big_lut_as_polynomial_list = PolynomialList::from_container(
        unsafe { slice::from_raw_parts(lut, small_lut_size * small_lut_count) },
        PolynomialSize(small_lut_size),
    );

    let bsk_glwe_size = GlweDimension(bsk_glwe_dimension).to_glwe_size().0;
    let fourier_bsk = FourierLweBootstrapKey::new(
        unsafe {
            slice::from_raw_parts(
                fourier_bsk as *const c64,
                bsk_input_lwe_dimension
                    * (bsk_polynomial_size / 2)
                    * bsk_decomposition_level_count
                    * bsk_glwe_size
                    * bsk_glwe_size,
            )
        },
        LweDimension(bsk_input_lwe_dimension),
        PolynomialSize(bsk_polynomial_size),
        GlweSize(bsk_glwe_size),
        DecompositionBaseLog(bsk_decomposition_base_log),
        DecompositionLevelCount(bsk_decomposition_level_count),
    );

    let lwe_out_size = LweDimension(ct_out_dimension).to_lwe_size();
    let lwe_list_out = LweList::from_container(
        unsafe { slice::from_raw_parts_mut(ct_out_vec, ct_out_count * lwe_out_size.0) },
        lwe_out_size,
    );

    let lwe_in_size = LweDimension(ct_in_dimension).to_lwe_size();
    let lwe_list_in = LweList::from_container(
        unsafe { slice::from_raw_parts(ct_in_vec, ct_in_count * lwe_in_size.0) },
        lwe_in_size,
    );

    let fpksk_list = LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
        unsafe {
            slice::from_raw_parts(
                fpksk,
                fpksk_decomposition_level_count
                    * fpksk_output_glwe_dimension
                    * fpksk_output_polynomial_size
                    * LweDimension(fpksk_input_dimension).to_lwe_size().0
                    * fpksk_count,
            )
        },
        DecompositionBaseLog(fpksk_decomposition_base_log),
        DecompositionLevelCount(fpksk_decomposition_level_count),
        LweDimension(fpksk_input_dimension),
        GlweDimension(fpksk_output_glwe_dimension),
        PolynomialSize(fpksk_output_polynomial_size),
        FunctionalPackingKeyswitchKeyCount(fpksk_count),
    );

    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list,
        fourier_bsk,
        lwe_list_out,
        lwe_list_in,
        fpksk_list,
        DecompositionLevelCount(cbs_decomposition_level_count),
        DecompositionBaseLog(cbs_decomposition_base_log),
        unsafe { (*fft).inner.as_view() },
        DynStack::new(unsafe { slice::from_raw_parts_mut(stack as _, stack_size) }),
    );
}
