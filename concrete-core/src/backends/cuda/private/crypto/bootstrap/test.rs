#[cfg(test)]
mod cuda_unit_test_pbs {
    use crate::commons::math::tensor::AsRefSlice;
    use crate::commons::test_tools::new_random_generator;
    use crate::prelude::*;
    use concrete_cuda::cuda_bind::{
        cleanup_cuda_bootstrap_amortized, scratch_cuda_bootstrap_amortized_64,
    };
    use std::error::Error;

    fn generate_accumulator_with_engine<F>(
        engine: &mut DefaultEngine,
        bootstrapping_key: &FftFourierLweBootstrapKey64,
        message_modulus: usize,
        carry_modulus: usize,
        f: F,
    ) -> Result<GlweCiphertext64, Box<dyn Error>>
    where
        F: Fn(u64) -> u64,
    {
        // Modulus of the msg contained in the msg bits and operations buffer
        let modulus_sup = message_modulus * carry_modulus;

        // N/(p/2) = size of each block
        let box_size = bootstrapping_key.polynomial_size().0 / modulus_sup;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / (modulus_sup) as u64;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; bootstrapping_key.polynomial_size().0];

        // This accumulator extracts the carry bits
        for i in 0..modulus_sup {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        // Everywhere
        let accumulator_plaintext = engine.create_plaintext_vector_from(&accumulator_u64)?;

        let accumulator = engine.trivially_encrypt_glwe_ciphertext(
            bootstrapping_key.glwe_dimension().to_glwe_size(),
            &accumulator_plaintext,
        )?;

        Ok(accumulator)
    }

    #[test]
    fn cuda_test_amortized_pbs() -> Result<(), Box<dyn Error>> {
        println!("cuda_test_pbs");
        // Shortint 2_2 params
        let lwe_dimension = LweDimension(500);
        let glwe_dimension = GlweDimension(1);
        let polynomial_sizes = vec![
            PolynomialSize(1024),
            PolynomialSize(2048),
            PolynomialSize(4096),
            PolynomialSize(8192),
        ];
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(2);
        let message_modulus: usize = 4;
        let carry_modulus: usize = 4;

        let payload_modulus = (message_modulus * carry_modulus) as u64;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / payload_modulus;

        // Unix seeder must be given a secret input.
        // Here we just give it 0, which is totally unsafe.
        const UNSAFE_SECRET: u128 = 0;

        let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
        let mut fft_engine = FftEngine::new(())?;

        let mut default_parallel_engine =
            DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;

        let repetitions = 1;
        let samples = 1;

        let mut error_sample_vec = Vec::<u64>::with_capacity(repetitions * samples);

        let mut generator = new_random_generator();
        for &polynomial_size in polynomial_sizes.iter() {
            println!("N = {}\n", polynomial_size.0);
            for _ in 0..repetitions {
                // Generate client-side keys

                // generate the lwe secret key
                let small_lwe_secret_key: LweSecretKey64 =
                    default_engine.generate_new_lwe_secret_key(lwe_dimension)?;

                // generate the rlwe secret key
                let glwe_secret_key: GlweSecretKey64 =
                    default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;

                let large_lwe_secret_key = default_engine
                    .transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

                // Convert into a variance for rlwe context
                let var_rlwe = Variance(glwe_modular_std_dev.get_variance());

                let bootstrap_key: LweBootstrapKey64 = default_parallel_engine
                    .generate_new_lwe_bootstrap_key(
                        &small_lwe_secret_key,
                        &glwe_secret_key,
                        pbs_base_log,
                        pbs_level,
                        var_rlwe,
                    )?;

                // Creation of the bootstrapping key in the Fourier domain

                // cuda
                let mut h_coef_bsk: Vec<u64> = vec![];
                h_coef_bsk.append(&mut bootstrap_key.0.tensor.as_slice().to_vec());

                let gpu_index = crate::backends::cuda::private::device::GpuIndex(0);
                let stream =
                    crate::backends::cuda::private::device::CudaStream::new(gpu_index).unwrap();

                let mut h_lut_vector_indexes = vec![0 as u32; 1];
                let mut d_lut_vector_indexes = stream.malloc::<u32>(1);
                let mut d_lut_pbs = stream.malloc::<u64>((2 * polynomial_size.0) as u32);
                let mut d_lwe_in = stream.malloc::<u64>((lwe_dimension.0 + 1) as u32);
                let mut d_lwe_out = stream.malloc::<u64>((polynomial_size.0 + 1) as u32);

                let bsk_size = (glwe_dimension.0 + 1)
                    * (glwe_dimension.0 + 1)
                    * polynomial_size.0
                    * pbs_level.0
                    * lwe_dimension.0;

                let mut d_bsk_fourier = stream.malloc::<f64>(bsk_size as u32);

                unsafe {
                    concrete_cuda::cuda_bind::cuda_convert_lwe_bootstrap_key_64(
                        d_bsk_fourier.as_mut_c_ptr(),
                        h_coef_bsk.as_ptr() as *mut std::os::raw::c_void,
                        stream.stream_handle().0,
                        gpu_index.0 as u32,
                        lwe_dimension.0 as u32,
                        glwe_dimension.0 as u32,
                        pbs_level.0 as u32,
                        polynomial_size.0 as u32,
                    );
                    stream.copy_to_gpu::<u32>(&mut d_lut_vector_indexes, &mut h_lut_vector_indexes);
                }

                let fourier_bsk: FftFourierLweBootstrapKey64 =
                    fft_engine.convert_lwe_bootstrap_key(&bootstrap_key)?;

                let accumulator = generate_accumulator_with_engine(
                    &mut default_engine,
                    &fourier_bsk,
                    message_modulus,
                    carry_modulus,
                    |x| x,
                )?;

                unsafe {
                    stream.copy_to_gpu::<u64>(
                        &mut d_lut_pbs,
                        &mut accumulator.0.tensor.as_slice().to_vec(),
                    );
                }

                // convert into a variance
                let var_lwe = Variance(lwe_modular_std_dev.get_variance());

                for _ in 0..samples {
                    let input_plaintext: u64 =
                        (generator.random_uniform::<u64>() % payload_modulus) * delta;

                    let plaintext = default_engine.create_plaintext_from(&input_plaintext)?;
                    let input = default_engine.encrypt_lwe_ciphertext(
                        &small_lwe_secret_key,
                        &plaintext,
                        var_lwe,
                    )?;

                    let mut output = default_engine
                        .zero_encrypt_lwe_ciphertext(&large_lwe_secret_key, var_lwe)?;

                    unsafe {
                        stream.copy_to_gpu::<u64>(
                            &mut d_lwe_in,
                            &mut input.0.tensor.as_slice().to_vec(),
                        );
                    }

                    unsafe {
                        let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
                        scratch_cuda_bootstrap_amortized_64(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            &mut pbs_buffer as *mut *mut i8,
                            glwe_dimension.0 as u32,
                            polynomial_size.0 as u32,
                            1,
                            stream.get_max_shared_memory().unwrap() as u32,
                            true,
                        );
                        concrete_cuda::cuda_bind::cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            d_lwe_out.as_mut_c_ptr(),
                            d_lut_pbs.as_c_ptr(),
                            d_lut_vector_indexes.as_c_ptr(),
                            d_lwe_in.as_c_ptr(),
                            d_bsk_fourier.as_c_ptr(),
                            pbs_buffer,
                            lwe_dimension.0 as u32,
                            glwe_dimension.0 as u32,
                            polynomial_size.0 as u32,
                            pbs_base_log.0 as u32,
                            pbs_level.0 as u32,
                            1,
                            1,
                            0,
                            stream.get_max_shared_memory().unwrap() as u32,
                        );
                        cleanup_cuda_bootstrap_amortized(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            &mut pbs_buffer as *mut *mut i8,
                        );
                    }
                    //println!("h_test_vector: {:?}", accumulator.0.get_body().tensor);
                    //fft_engine.discard_bootstrap_lwe_ciphertext(
                    //    &mut output,
                    //    &input,
                    //    &accumulator,
                    //    &fourier_bsk,
                    //)?;
                    //println!("h_lwe_out: {:?}", output.0.tensor);
                    let mut h_output: Vec<u64> = vec![0; polynomial_size.0 + 1];
                    unsafe {
                        stream.copy_to_cpu::<u64>(&mut h_output, &mut d_lwe_out);
                    }
                    output.0.tensor.as_mut_container().clone_from(&h_output);
                    //println!("h_output: {:?}", output);
                    // decryption
                    let decrypted =
                        default_engine.decrypt_lwe_ciphertext(&large_lwe_secret_key, &output)?;

                    if decrypted == plaintext {
                        panic!("Equal {decrypted:?}, {plaintext:?}");
                    }

                    let mut decrypted_u64: u64 = 0;
                    default_engine.discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

                    // let err = if decrypted_u64 >= input_plaintext {
                    //     decrypted_u64 - input_plaintext
                    // } else {
                    //     input_plaintext - decrypted_u64
                    // };

                    let err = {
                        let d0 = decrypted_u64.wrapping_sub(input_plaintext);
                        let d1 = input_plaintext.wrapping_sub(decrypted_u64);
                        std::cmp::min(d0, d1)
                    };

                    // let err = torus_modular_distance(input_plaintext, decrypted_u64);

                    error_sample_vec.push(err);

                    //The bit before the message
                    let rounding_bit = delta >> 1;

                    //compute the rounding bit
                    let rounding = (decrypted_u64 & rounding_bit) << 1;

                    let decoded = (decrypted_u64.wrapping_add(rounding)) / delta;

                    assert_eq!(decoded, input_plaintext / delta);
                }
            }

            error_sample_vec.sort();

            let bit_errors: Vec<_> = error_sample_vec
                .iter()
                .map(|&x| if x != 0 { 63 - x.leading_zeros() } else { 0 })
                .collect();

            let mean_bit_errors: u32 = bit_errors.iter().sum::<u32>() / bit_errors.len() as u32;
            let mean_bit_errors_f64: f64 =
                bit_errors.iter().map(|&x| x as f64).sum::<f64>() / bit_errors.len() as f64;

            for (idx, (&val, &bit_error)) in
                error_sample_vec.iter().zip(bit_errors.iter()).enumerate()
            {
                println!("#{idx}: Error {val}, bit_error {bit_error}");
            }

            println!("Mean bit error: {mean_bit_errors}");
            println!("Mean bit error f64: {mean_bit_errors_f64}");
        }

        Ok(())
    }

    #[test]
    fn cuda_test_low_lat_pbs() -> Result<(), Box<dyn Error>> {
        println!("cuda_test_pbs");
        // Shortint 2_2 params
        let lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_sizes = vec![
            PolynomialSize(1024),
            PolynomialSize(2048),
            PolynomialSize(4096),
            PolynomialSize(8192),
        ];
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(2);
        let message_modulus: usize = 4;
        let carry_modulus: usize = 4;

        let payload_modulus = (message_modulus * carry_modulus) as u64;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / payload_modulus;

        // Unix seeder must be given a secret input.
        // Here we just give it 0, which is totally unsafe.
        const UNSAFE_SECRET: u128 = 0;

        let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
        let mut fft_engine = FftEngine::new(())?;

        let mut default_parallel_engine =
            DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;

        let repetitions = 1;
        let samples = 1;

        let mut error_sample_vec = Vec::<u64>::with_capacity(repetitions * samples);

        let mut generator = new_random_generator();
        for &polynomial_size in polynomial_sizes.iter() {
            println!("N = {}\n", polynomial_size.0);
            for _ in 0..repetitions {
                // Generate client-side keys

                // generate the lwe secret key
                let small_lwe_secret_key: LweSecretKey64 =
                    default_engine.generate_new_lwe_secret_key(lwe_dimension)?;

                // generate the rlwe secret key
                let glwe_secret_key: GlweSecretKey64 =
                    default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;

                let large_lwe_secret_key = default_engine
                    .transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

                // Convert into a variance for rlwe context
                let var_rlwe = Variance(glwe_modular_std_dev.get_variance());

                let bootstrap_key: LweBootstrapKey64 = default_parallel_engine
                    .generate_new_lwe_bootstrap_key(
                        &small_lwe_secret_key,
                        &glwe_secret_key,
                        pbs_base_log,
                        pbs_level,
                        var_rlwe,
                    )?;

                // Creation of the bootstrapping key in the Fourier domain

                // cuda
                let mut h_coef_bsk: Vec<u64> = vec![];
                h_coef_bsk.append(&mut bootstrap_key.0.tensor.as_slice().to_vec());

                let gpu_index = crate::backends::cuda::private::device::GpuIndex(0);
                let stream =
                    crate::backends::cuda::private::device::CudaStream::new(gpu_index).unwrap();

                let mut h_lut_vector_indexes = vec![0 as u32; 1];
                let mut d_lut_vector_indexes = stream.malloc::<u32>(1);
                let mut d_lut_pbs = stream.malloc::<u64>((2 * polynomial_size.0) as u32);
                let mut d_lwe_in = stream.malloc::<u64>((lwe_dimension.0 + 1) as u32);
                let mut d_lwe_out = stream.malloc::<u64>((polynomial_size.0 + 1) as u32);

                let bsk_size = (glwe_dimension.0 + 1)
                    * (glwe_dimension.0 + 1)
                    * polynomial_size.0
                    * pbs_level.0
                    * lwe_dimension.0;

                let mut d_bsk_fourier = stream.malloc::<f64>(bsk_size as u32);

                unsafe {
                    concrete_cuda::cuda_bind::cuda_convert_lwe_bootstrap_key_64(
                        d_bsk_fourier.as_mut_c_ptr(),
                        h_coef_bsk.as_ptr() as *mut std::os::raw::c_void,
                        stream.stream_handle().0,
                        gpu_index.0 as u32,
                        lwe_dimension.0 as u32,
                        glwe_dimension.0 as u32,
                        pbs_level.0 as u32,
                        polynomial_size.0 as u32,
                    );
                    stream.copy_to_gpu::<u32>(&mut d_lut_vector_indexes, &mut h_lut_vector_indexes);
                }

                let fourier_bsk: FftFourierLweBootstrapKey64 =
                    fft_engine.convert_lwe_bootstrap_key(&bootstrap_key)?;

                let accumulator = generate_accumulator_with_engine(
                    &mut default_engine,
                    &fourier_bsk,
                    message_modulus,
                    carry_modulus,
                    |x| x,
                )?;

                unsafe {
                    stream.copy_to_gpu::<u64>(
                        &mut d_lut_pbs,
                        &mut accumulator.0.tensor.as_slice().to_vec(),
                    );
                }

                // convert into a variance
                let var_lwe = Variance(lwe_modular_std_dev.get_variance());

                for _ in 0..samples {
                    let input_plaintext: u64 =
                        (generator.random_uniform::<u64>() % payload_modulus) * delta;

                    let plaintext = default_engine.create_plaintext_from(&input_plaintext)?;
                    let input = default_engine.encrypt_lwe_ciphertext(
                        &small_lwe_secret_key,
                        &plaintext,
                        var_lwe,
                    )?;

                    let mut output = default_engine
                        .zero_encrypt_lwe_ciphertext(&large_lwe_secret_key, var_lwe)?;

                    unsafe {
                        stream.copy_to_gpu::<u64>(
                            &mut d_lwe_in,
                            &mut input.0.tensor.as_slice().to_vec(),
                        );
                    }

                    unsafe {
                        let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
                        concrete_cuda::cuda_bind::scratch_cuda_bootstrap_low_latency_64(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            &mut pbs_buffer as *mut *mut i8,
                            glwe_dimension.0 as u32,
                            polynomial_size.0 as u32,
                            pbs_level.0 as u32,
                            1,
                            stream.get_max_shared_memory().unwrap() as u32,
                            true,
                        );

                        concrete_cuda::cuda_bind::cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            d_lwe_out.as_mut_c_ptr(),
                            d_lut_pbs.as_c_ptr(),
                            d_lut_vector_indexes.as_c_ptr(),
                            d_lwe_in.as_c_ptr(),
                            d_bsk_fourier.as_c_ptr(),
                            pbs_buffer,
                            lwe_dimension.0 as u32,
                            glwe_dimension.0 as u32,
                            polynomial_size.0 as u32,
                            pbs_base_log.0 as u32,
                            pbs_level.0 as u32,
                            1,
                            1,
                            0,
                            stream.get_max_shared_memory().unwrap() as u32,
                        );
                        concrete_cuda::cuda_bind::cleanup_cuda_bootstrap_low_latency(
                            stream.stream_handle().0,
                            gpu_index.0 as u32,
                            &mut pbs_buffer as *mut *mut i8,
                        );
                    }
                    //println!("h_test_vector: {:?}", accumulator.0.get_body().tensor);
                    //fft_engine.discard_bootstrap_lwe_ciphertext(
                    //    &mut output,
                    //    &input,
                    //    &accumulator,
                    //    &fourier_bsk,
                    //)?;
                    //println!("h_lwe_out: {:?}", output.0.tensor);
                    let mut h_output: Vec<u64> = vec![0; polynomial_size.0 + 1];
                    unsafe {
                        stream.copy_to_cpu::<u64>(&mut h_output, &mut d_lwe_out);
                    }
                    output.0.tensor.as_mut_container().clone_from(&h_output);
                    //println!("h_output: {:?}", output);
                    // decryption
                    let decrypted =
                        default_engine.decrypt_lwe_ciphertext(&large_lwe_secret_key, &output)?;

                    if decrypted == plaintext {
                        panic!("Equal {decrypted:?}, {plaintext:?}");
                    }

                    let mut decrypted_u64: u64 = 0;
                    default_engine.discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

                    // let err = if decrypted_u64 >= input_plaintext {
                    //     decrypted_u64 - input_plaintext
                    // } else {
                    //     input_plaintext - decrypted_u64
                    // };

                    let err = {
                        let d0 = decrypted_u64.wrapping_sub(input_plaintext);
                        let d1 = input_plaintext.wrapping_sub(decrypted_u64);
                        std::cmp::min(d0, d1)
                    };

                    // let err = torus_modular_distance(input_plaintext, decrypted_u64);

                    error_sample_vec.push(err);

                    //The bit before the message
                    let rounding_bit = delta >> 1;

                    //compute the rounding bit
                    let rounding = (decrypted_u64 & rounding_bit) << 1;

                    let decoded = (decrypted_u64.wrapping_add(rounding)) / delta;

                    assert_eq!(decoded, input_plaintext / delta);
                }
            }

            error_sample_vec.sort();

            let bit_errors: Vec<_> = error_sample_vec
                .iter()
                .map(|&x| if x != 0 { 63 - x.leading_zeros() } else { 0 })
                .collect();

            let mean_bit_errors: u32 = bit_errors.iter().sum::<u32>() / bit_errors.len() as u32;
            let mean_bit_errors_f64: f64 =
                bit_errors.iter().map(|&x| x as f64).sum::<f64>() / bit_errors.len() as f64;

            for (idx, (&val, &bit_error)) in
                error_sample_vec.iter().zip(bit_errors.iter()).enumerate()
            {
                println!("#{idx}: Error {val}, bit_error {bit_error}");
            }

            println!("Mean bit error: {mean_bit_errors}");
            println!("Mean bit error f64: {mean_bit_errors_f64}");
        }

        Ok(())
    }
}
