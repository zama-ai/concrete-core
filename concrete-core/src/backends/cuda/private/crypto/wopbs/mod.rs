use crate::backends::cuda::private::crypto::bootstrap::CudaBootstrapKey;
use crate::backends::cuda::private::crypto::keyswitch::{CudaLweKeyswitchKey, CudaLwePrivateFunctionalPackingKeyswitchKeyList};
use crate::backends::cuda::private::crypto::lwe::list::CudaLweList;
use crate::backends::cuda::private::crypto::plaintext::list::CudaPlaintextList;
use crate::backends::cuda::private::device::{CudaStream, GpuIndex};
use crate::backends::fft::private::crypto::bootstrap::FourierLweBootstrapKeyView;
use crate::backends::fft::private::crypto::wop_pbs::{
    circuit_bootstrap_boolean, FourierGgswCiphertextListMutView,
};
use crate::backends::fft::private::math::fft::FftView;
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
use crate::commons::crypto::lwe::{LweCiphertext, LweList};
use crate::commons::math::polynomial::PolynomialList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::commons::numeric::UnsignedInteger;
use crate::commons::utils::izip;
use crate::prelude::{DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, GgswCiphertext64, GgswCiphertextEntity, LweCiphertext64, LweDimension, MessageBitsCount, PolynomialCount, SharedMemoryAmount};
use aligned_vec::CACHELINE_ALIGN;
use concrete_cuda::cuda_bind::{cuda_blind_rotate_and_sample_extraction_64, cuda_cmux_tree_64};
use concrete_fft::c64;
use dyn_stack::{DynStack, ReborrowMut};

#[cfg(test)]
mod test;

// GGSW ciphertexts are stored from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn cuda_vertical_packing(
    tree_lut: &[Vec<u64>],
    vec_ggsw: &[GgswCiphertext64],
    level: DecompositionLevelCount,
    base_log: DecompositionBaseLog,
    r: usize,
) -> LweCiphertext64 {
    let polynomial_size = vec_ggsw[0].polynomial_size();
    let glwe_dimension = vec_ggsw[0].glwe_dimension();
    let glwe_size = glwe_dimension.to_glwe_size().0 * polynomial_size.0;

    println!("vec_ggsw size: {}", vec_ggsw.len());

    let gpu_index = GpuIndex(0);
    let stream = CudaStream::new(gpu_index).unwrap();

    // LUTs
    let mut h_concatenated_luts_glwe = vec![];
    for h_lut in tree_lut.iter() {
        let mut h_lut = h_lut.clone();
        h_concatenated_luts_glwe.append(&mut h_lut);
    }
    let mut d_concatenated_luts_glwe = stream.malloc::<u64>(h_concatenated_luts_glwe.len() as u32);
    unsafe {
        stream.copy_to_gpu::<u64>(
            &mut d_concatenated_luts_glwe,
            h_concatenated_luts_glwe.as_slice(),
        );
    }

    let mut d_result_br = stream.malloc::<u64>(glwe_size as u32);

    if tree_lut.len() == (1 << r) {
        assert_eq!(h_concatenated_luts_glwe.len(), (1 << r) * polynomial_size.0);
        let mut d_result_cmux = stream.malloc::<u64>(glwe_size as u32);

        // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
        // the last blind rotation.
        let (cmux_ggsw, br_ggsw) = vec_ggsw.split_at(r);

        // mbr GGSWs
        let mut h_concatenated_br_ggsw = vec![];
        for ggsw in br_ggsw.iter() {
            let ggsw_slice = ggsw.0.as_tensor().as_slice();
            h_concatenated_br_ggsw.append(&mut ggsw_slice.to_vec());
        }
        let mut d_concatenated_br_ggsw = stream.malloc::<u64>(h_concatenated_br_ggsw.len() as u32);
        unsafe {
            stream.copy_to_gpu::<u64>(
                &mut d_concatenated_br_ggsw,
                h_concatenated_br_ggsw.as_slice(),
            );
        }

        // mtree GGSWs
        let mut h_concatenated_cmux_ggsw = vec![];
        for ggsw in cmux_ggsw.iter() {
            let ggsw_slice = ggsw.0.as_tensor().as_slice();
            h_concatenated_cmux_ggsw.append(&mut ggsw_slice.to_vec());
        }
        let mut d_concatenated_cmux_ggsw =
            stream.malloc::<u64>(h_concatenated_cmux_ggsw.len() as u32);
        unsafe {
            stream.copy_to_gpu::<u64>(
                &mut d_concatenated_cmux_ggsw,
                h_concatenated_cmux_ggsw.as_slice(),
            );
        }

        // CMUX Tree
        unsafe {
            cuda_cmux_tree_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_result_cmux.as_mut_c_ptr(),
                d_concatenated_cmux_ggsw.as_c_ptr(),
                d_concatenated_luts_glwe.as_c_ptr(),
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                cmux_ggsw.len() as u32,
                1,
                stream.get_max_shared_memory().unwrap() as u32,
            );
        }
        // Blind rotation + sample extraction
        unsafe {
            cuda_blind_rotate_and_sample_extraction_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_result_br.as_mut_c_ptr(),
                d_concatenated_br_ggsw.as_c_ptr(),
                d_result_cmux.as_c_ptr(),
                br_ggsw.len() as u32,
                1u32, // tau
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                stream.get_max_shared_memory().unwrap() as u32,
            );
        }
    } else {
        // mbr GGSWs
        let mut h_concatenated_br_ggsw = vec![];
        for ggsw in vec_ggsw.iter() {
            let ggsw_slice = ggsw.0.as_tensor().as_slice();
            h_concatenated_br_ggsw.append(&mut ggsw_slice.to_vec());
        }
        let mut d_concatenated_br_ggsw = stream.malloc::<u64>(h_concatenated_br_ggsw.len() as u32);
        unsafe {
            stream.copy_to_gpu::<u64>(
                &mut d_concatenated_br_ggsw,
                h_concatenated_br_ggsw.as_slice(),
            );
        }

        // Blind rotation + sample extraction
        unsafe {
            cuda_blind_rotate_and_sample_extraction_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_result_br.as_mut_c_ptr(),
                d_concatenated_br_ggsw.as_c_ptr(),
                d_concatenated_luts_glwe.as_c_ptr(),
                vec_ggsw.len() as u32,
                tree_lut.len() as u32, // tau
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                stream.get_max_shared_memory().unwrap() as u32,
            );
        }
    }

    // Check the result
    let lwe_dimension = LweDimension(polynomial_size.0 * glwe_dimension.0);
    // sample extract of the RLWE of the Vertical packing
    let mut h_result = vec![41u64; lwe_dimension.to_lwe_size().0];
    unsafe {
        stream.copy_to_cpu::<u64>(&mut h_result, &d_result_br);
    }

    LweCiphertext64(LweCiphertext::from_container(h_result))
}

/// Perform a circuit bootstrap followed by a vertical packing on ciphertexts encrypting boolean
/// messages.
///
/// The circuit bootstrapping uses the private functional packing key switch.
///
/// This is supposed to be used only with boolean (1 bit of message) LWE ciphertexts.
#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_boolean_cuda_vertical_packing(
    big_lut_as_polynomial_list: PolynomialList<&[u64]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_list_out: LweList<&mut [u64]>,
    lwe_list_in: LweList<&[u64]>,
    fpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[u64]>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) {
    let glwe_size = fpksk_list.output_glwe_key_dimension().to_glwe_size();
    let (mut ggsw_list_data, stack) = stack.make_aligned_with(
        lwe_list_in.count().0 * fpksk_list.output_polynomial_size().0 / 2
            * glwe_size.0
            * glwe_size.0
            * level_cbs.0,
        CACHELINE_ALIGN,
        |_| c64::default(),
    );
    let (mut ggsw_res_data, mut stack) = stack.make_aligned_with(
        fpksk_list.output_polynomial_size().0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
        CACHELINE_ALIGN,
        |_| 0u64,
    );

    let mut alt_ggsw_vec = vec![];

    let mut ggsw_list = FourierGgswCiphertextListMutView::new(
        &mut ggsw_list_data,
        lwe_list_in.count().0,
        fpksk_list.output_polynomial_size(),
        glwe_size,
        base_log_cbs,
        level_cbs,
    );

    let mut ggsw_res = StandardGgswCiphertext::from_container(
        &mut *ggsw_res_data,
        glwe_size,
        fpksk_list.output_polynomial_size(),
        base_log_cbs,
    );

    // let mut fft_engine = FftEngine::new(()).unwrap();
    for (lwe_in, ggsw) in izip!(
        lwe_list_in.ciphertext_iter(),
        ggsw_list.as_mut_view().into_ggsw_iter(),
    ) {
        circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog(64 - 1),
            fpksk_list,
            fft,
            stack.rb_mut(),
        );

        let ggsw_alt = GgswCiphertext64(StandardGgswCiphertext::from_container(
            ggsw_res.as_mut_view().into_container().to_vec(),
            glwe_size,
            fpksk_list.output_polynomial_size(),
            base_log_cbs,
        ));
        alt_ggsw_vec.push(ggsw_alt);

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack.rb_mut());
    }

    // We deduce the number of luts in the vec_lut from the number of cipherxtexts in lwe_list_out
    let number_of_luts = lwe_list_out.count().0;

    let small_lut_size =
        PolynomialCount(big_lut_as_polynomial_list.polynomial_count().0 / number_of_luts);

    // Convert fourier GGSWs back to standard GGSWs
    // let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(0))).unwrap();

    // let input = 42_u64;
    // let plaintext: Plaintext64 = default_engine.create_plaintext_from(&input).unwrap();

    println!("number_of_luts size: {}", number_of_luts);
    println!(
        "big_lut_as_polynomial_list size: {}",
        big_lut_as_polynomial_list.polynomial_count().0
    );
    println!("ggsw_list size: {}", ggsw_list.count());

    for (lut, mut lwe_out) in izip!(
        big_lut_as_polynomial_list.sublist_iter(small_lut_size),
        lwe_list_out.ciphertext_iter_mut(),
    ) {
        let mut h_luts = vec![];
        for polynomial in lut.polynomial_iter() {
            let mut poly = polynomial.as_tensor().as_slice().to_vec();
            let mut h_zeroes = vec![0_u64; fpksk_list.output_polynomial_size().0];

            let mut h_lut = vec![];
            // Mask is zero
            h_lut.append(&mut h_zeroes);
            // Body is something else
            h_lut.append(&mut poly);

            h_luts.push(h_lut);
        }

        // let mut lwe_out_cpu = LweCiphertext
        // vertical_packing(lut, lwe_out.as_mut_view(), ggsw_list.as_view(), fft, stack.rb_mut());

        let mut result = cuda_vertical_packing(
            &h_luts,
            &alt_ggsw_vec,
            level_cbs,
            base_log_cbs,
            number_of_luts,
        );
        // assert_eq!(result.0.as_mut_view().into_container(),
        // lwe_out.as_mut_view().into_container());
        lwe_out.update_with_add(&result.0.as_mut_view());
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn execute_circuit_bootstrap_vertical_packing_on_gpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    lwe_array_out: &mut CudaLweList<T>,
    lwe_array_in: &CudaLweList<T>,
    lut_vector: &CudaPlaintextList<T>,
    bsk: &CudaBootstrapKey<T>,
    cbs_fpksk: &CudaLwePrivateFunctionalPackingKeyswitchKeyList<T>,
    level_count_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    cuda_shared_memory: SharedMemoryAmount,
) {
    let stream = &streams[0];
    let lut_number = lwe_array_out.lwe_ciphertext_count.0;
    stream.initialize_twiddles(bsk.polynomial_size);
    stream.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector::<T>(
        lwe_array_out.d_vecs.get_mut(0).unwrap(),
        lwe_array_in.d_vecs.get(0).unwrap(),
        lut_vector.d_vecs.get(0).unwrap(),
        bsk.d_vecs.get(0).unwrap(),
        cbs_fpksk.d_vecs.get(0).unwrap(),
        bsk.glwe_dimension,
        lwe_array_in.lwe_dimension,
        bsk.polynomial_size,
        bsk.decomp_level,
        bsk.decomp_base_log,
        cbs_fpksk.decomposition_level_count,
        cbs_fpksk.decomposition_base_log,
        level_count_cbs,
        base_log_cbs,
        lwe_array_in.lwe_ciphertext_count,
        lut_number,
        cuda_shared_memory,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn execute_wop_pbs_on_gpu<T: UnsignedInteger>(
    streams: &[CudaStream],
    lwe_array_out: &mut CudaLweList<T>,
    lwe_array_in: &CudaLweList<T>,
    lut_vector: &CudaPlaintextList<T>,
    bsk: &CudaBootstrapKey<T>,
    ksk: &CudaLweKeyswitchKey<T>,
    cbs_fpksk: &CudaLwePrivateFunctionalPackingKeyswitchKeyList<T>,
    level_count_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    number_of_bits_of_message: MessageBitsCount,
    cuda_shared_memory: SharedMemoryAmount,
) {
    let stream = &streams[0];
    stream.initialize_twiddles(bsk.polynomial_size);
    stream.discard_wop_pbs_lwe_ciphertext_vector::<T>(
        lwe_array_out.d_vecs.get_mut(0).unwrap(),
        lwe_array_in.d_vecs.get(0).unwrap(),
        lut_vector.d_vecs.get(0).unwrap(),
        bsk.d_vecs.get(0).unwrap(),
        ksk.d_vecs.get(0).unwrap(),
        cbs_fpksk.d_vecs.get(0).unwrap(),
        bsk.glwe_dimension,
        lwe_array_in.lwe_dimension,
        bsk.polynomial_size,
        bsk.decomp_base_log,
        bsk.decomp_level,
        ksk.decomp_base_log,
        ksk.decomp_level,
        cbs_fpksk.decomposition_base_log,
        cbs_fpksk.decomposition_level_count,
        base_log_cbs,
        level_count_cbs,
        number_of_bits_of_message,
        ExtractedBitsCount(number_of_bits_of_message.0),
        lwe_array_in.lwe_ciphertext_count,
        cuda_shared_memory,
    );
}
