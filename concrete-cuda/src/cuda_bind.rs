use std::ffi::c_void;

#[link(name = "concrete_cuda", kind = "static")]
extern "C" {

    pub fn cuda_create_stream(gpu_index: u32) -> *mut c_void;

    pub fn cuda_destroy_stream(v_stream: *mut c_void, gpu_index: u32) -> i32;

    pub fn cuda_malloc(size: u64, gpu_index: u32) -> *mut c_void;

    pub fn cuda_check_valid_malloc(size: u64, gpu_index: u32) -> i32;

    pub fn cuda_memcpy_async_to_cpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        v_stream: *mut c_void,
        gpu_index: u32,
    ) -> i32;

    pub fn cuda_memcpy_async_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        v_stream: *mut c_void,
        gpu_index: u32,
    ) -> i32;

    pub fn cuda_get_number_of_gpus() -> i32;

    pub fn cuda_synchronize_device(gpu_index: u32) -> i32;

    pub fn cuda_drop(ptr: *mut c_void, gpu_index: u32) -> i32;

    pub fn cuda_get_max_shared_memory(gpu_index: u32) -> i32;

    pub fn cuda_initialize_twiddles(polynomial_size: u32, gpu_index: u32);

    pub fn cuda_convert_lwe_bootstrap_key_32(
        dest: *mut c_void,
        src: *mut c_void,
        v_stream: *const c_void,
        gpu_index: u32,
        input_lwe_dim: u32,
        glwe_dim: u32,
        l_gadget: u32,
        polynomial_size: u32,
    );

    pub fn cuda_convert_lwe_bootstrap_key_64(
        dest: *mut c_void,
        src: *mut c_void,
        v_stream: *const c_void,
        gpu_index: u32,
        input_lwe_dim: u32,
        glwe_dim: u32,
        l_gadget: u32,
        polynomial_size: u32,
    );

    pub fn cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
        v_stream: *mut c_void,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        num_test_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
        v_stream: *mut c_void,
        lwe_out: *mut c_void,
        test_vector: *const c_void,
        test_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        num_test_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
        v_stream: *mut c_void,
        lwe_out: *mut c_void,
        lut_vector: *const c_void,
        lut_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        num_lut_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
        v_stream: *mut c_void,
        lwe_out: *mut c_void,
        lut_vector: *const c_void,
        lut_vector_indexes: *const c_void,
        lwe_in: *const c_void,
        bootstrapping_key: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        num_lut_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_keyswitch_lwe_ciphertext_vector_32(
        v_stream: *const c_void,
        lwe_out: *mut c_void,
        lwe_in: *const c_void,
        keyswitch_key: *const c_void,
        input_lwe_dimension: u32,
        output_lwe_dimension: u32,
        base_log: u32,
        l_gadget: u32,
        num_samples: u32,
    );

    pub fn cuda_keyswitch_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
        lwe_out: *mut c_void,
        lwe_in: *const c_void,
        keyswitch_key: *const c_void,
        input_lwe_dimension: u32,
        output_lwe_dimension: u32,
        base_log: u32,
        l_gadget: u32,
        num_samples: u32,
    );

    pub fn cuda_cmux_tree_32(
        v_stream: *const c_void,
        glwe_out: *mut c_void,
        ggsw_in: *const c_void,
        lut_vector: *const c_void,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        l_gadget: u32,
        r: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_cmux_tree_64(
        v_stream: *const c_void,
        glwe_out: *mut c_void,
        ggsw_in: *const c_void,
        lut_vector: *const c_void,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        l_gadget: u32,
        r: u32,
        max_shared_memory: u32,
    );

    pub fn cuda_extract_bits_32(
        v_stream: *const c_void,
        list_lwe_out: *mut c_void,
        lwe_in: *const c_void,
        lwe_in_buffer: *mut c_void,
        lwe_in_shifted_buffer: *mut c_void,
        lwe_out_ks_buffer: *mut c_void,
        lwe_out_pbs_buffer: *mut c_void,
        lut_pbs: *mut c_void,
        lut_vector_indexes: *const c_void,
        ksk: *const c_void,
        fourier_bsk: *const c_void,
        number_of_bits: u32,
        delta_log: u32,
        lwe_dimension_before: u32,
        lwe_dimension_after: u32,
        glwe_dimension: u32,
        base_log_bsk: u32,
        l_gadget_bsk: u32,
        base_log_ksk: u32,
        l_gadget_ksk: u32,
        number_of_samples: u32,
    );

    pub fn cuda_extract_bits_64(
        v_stream: *const c_void,
        list_lwe_out: *mut c_void,
        lwe_in: *const c_void,
        lwe_in_buffer: *mut c_void,
        lwe_in_shifted_buffer: *mut c_void,
        lwe_out_ks_buffer: *mut c_void,
        lwe_out_pbs_buffer: *mut c_void,
        lut_pbs: *mut c_void,
        lut_vector_indexes: *const c_void,
        ksk: *const c_void,
        fourier_bsk: *const c_void,
        number_of_bits: u32,
        delta_log: u32,
        lwe_dimension_before: u32,
        lwe_dimension_after: u32,
        glwe_dimension: u32,
        base_log_bsk: u32,
        l_gadget_bsk: u32,
        base_log_ksk: u32,
        l_gadget_ksk: u32,
        number_of_samples: u32,
    );
}
