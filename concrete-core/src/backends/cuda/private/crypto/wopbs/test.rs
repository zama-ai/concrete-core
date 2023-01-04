use crate::backends::cuda::private::crypto::ggsw::ciphertext::CudaGgswCiphertext;
use crate::backends::cuda::private::crypto::wopbs::{
    circuit_bootstrap_boolean_cuda_vertical_packing,
    execute_circuit_bootstrap_vertical_packing_on_gpu,
};
use crate::backends::cuda::private::device::{CudaStream, GpuIndex};
use crate::backends::fft::private::crypto::bootstrap::{
    fill_with_forward_fourier_scratch, FourierLweBootstrapKey,
};
use crate::backends::fft::private::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
    circuit_bootstrap_boolean_vertical_packing_scratch, extract_bits, extract_bits_scratch,
};
use crate::backends::fft::private::math::fft::Fft;
use crate::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::{GlweCiphertext, LwePrivateFunctionalPackingKeyswitchKeyList};
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::commons::math::decomposition::SignedDecomposer;
use crate::commons::math::polynomial::PolynomialList;
use crate::commons::math::tensor::{AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::test_tools;
use crate::commons::utils::izip;
use crate::prelude::*;
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::UnixSeeder;
use concrete_cuda::cuda_bind::{
    cuda_circuit_bootstrap_64, cuda_cmux_tree_64, cuda_convert_lwe_bootstrap_key_64,
    cuda_extract_bits_64, cuda_initialize_twiddles, cuda_synchronize_device, cuda_wop_pbs_64,
};
use concrete_fft::c64;
use dyn_stack::{DynStack, GlobalMemBuffer};
use std::os::raw::c_void;

#[test]
pub fn test_cuda_cmux_tree() {
    let polynomial_sizes = vec![
        PolynomialSize(512),
        PolynomialSize(1024),
        PolynomialSize(2048),
        PolynomialSize(4096),
    ];
    let glwe_dimension = GlweDimension(1);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(6);
    let delta_log = 60;

    let std = LogStandardDev::from_log_standard_dev(-60.);

    for polynomial_size in polynomial_sizes.into_iter() {
        println!(
            "polynomial_size: {}, glwe_dimension: {}, level: {}, base_log: {}",
            polynomial_size.0, glwe_dimension.0, level.0, base_log.0
        );

        let r = 10; // Depth of the tree
        let tau = 10; // Quantity of trees
        let num_lut = 1 << r;

        // Size of a GGSW ciphertext
        // N * (k+1) * (k+1) * ell
        let ggsw_size = polynomial_size.0
            * glwe_dimension.to_glwe_size().0
            * glwe_dimension.to_glwe_size().0
            * level.0;
        // Size of a GLWE ciphertext
        // (k+1) * N
        let glwe_size = glwe_dimension.to_glwe_size().0 * polynomial_size.0;

        println!("r: {}", r);
        println!("tau: {}", tau);
        println!("glwe_size: {}, ggsw_size: {}", glwe_size, ggsw_size);

        // Engines
        const UNSAFE_SECRET: u128 = 0;
        let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

        // Key
        let mut secret_generator =
            SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);
        let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
            GlweSecretKey::generate_binary(glwe_dimension, polynomial_size, &mut secret_generator);

        // Instantiate the LUTs
        // We need 2^r GLWEs
        let mut h_concatenated_luts = vec![];
        let mut h_luts =
            PolynomialList::allocate(0u64, PolynomialCount(num_lut * tau), polynomial_size);
        for (i, mut polynomial) in h_luts.polynomial_iter_mut().enumerate() {
            let tree_offset = i / num_lut;
            polynomial.as_mut_tensor().fill_with_element(
                ((i + tree_offset) as u64 % (1 << (64 - delta_log))) << delta_log,
            );

            let mut h_lut = polynomial.as_tensor().as_slice().to_vec();
            // let mut h_zeroes = vec![0_u64; polynomial_size.0];
            // println!("lut {}) {}", i, h_lut[0]);

            // Mask is zero
            // h_concatenated_luts.append(&mut h_zeroes);
            // Body is something else
            h_concatenated_luts.append(&mut h_lut);
        }

        // Now we have (2**r GLWE ciphertexts)
        assert_eq!(h_concatenated_luts.len(), num_lut * tau * polynomial_size.0);
        println!("\nWe have {} LUTs", num_lut);

        // Copy to Device
        let gpu_index = GpuIndex(0);
        let stream = CudaStream::new(gpu_index).unwrap();

        let mut d_concatenated_luts = stream.malloc::<u64>(h_concatenated_luts.len() as u32);
        unsafe {
            stream.copy_to_gpu::<u64>(&mut d_concatenated_luts, h_concatenated_luts.as_slice());
        }

        // Instantiate the GGSW m^tree ciphertexts
        // We need r GGSW ciphertexts
        // Bit decomposition of the value from MSB to LSB
        let mut value = 0b111101;
        let base_witness = value;
        println!("base witness: {}", value);
        //bit decomposition of the value
        let mut vec_message = vec![Plaintext(0); r as usize];
        for i in 0..r {
            vec_message[i as usize] = Plaintext(value & 1);
            value >>= 1;
        }

        // bit decomposition are stored in ggsw
        let mut h_concatenated_ggsw = vec![];
        for vec_msg in vec_message.iter().take(r as usize) {
            println!("vec_msg: {}", vec_msg.0);

            let mut ggsw = StandardGgswCiphertext::allocate(
                0 as u64,
                polynomial_size,
                glwe_dimension.to_glwe_size(),
                level,
                base_log,
            );
            rlwe_sk.encrypt_constant_ggsw(&mut ggsw, vec_msg, std, &mut encryption_generator);

            let ggsw_slice = ggsw.as_tensor().as_slice();
            h_concatenated_ggsw.append(&mut ggsw_slice.to_vec());
        }

        assert_eq!(h_concatenated_ggsw.len(), (r as usize) * ggsw_size);
        println!("We have {} ggsw", r);

        // Copy to Device
        let mut d_concatenated_mtree = stream.malloc::<u64>(h_concatenated_ggsw.len() as u32);
        unsafe {
            stream.copy_to_gpu::<u64>(&mut d_concatenated_mtree, h_concatenated_ggsw.as_slice());
        }

        let mut d_results = stream.malloc::<u64>((tau * glwe_size) as u32);
        unsafe {
            cuda_cmux_tree_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_results.as_mut_c_ptr(),
                d_concatenated_mtree.as_c_ptr(),
                d_concatenated_luts.as_c_ptr(),
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                r as u32,
                tau as u32,
                stream.get_max_shared_memory().unwrap() as u32,
            );
        }

        let mut h_results = vec![49u64; tau * glwe_size];
        unsafe {
            stream.copy_to_cpu::<u64>(&mut h_results, &d_results);
        }
        assert_eq!(h_results.len(), tau * glwe_size);

        for (i, h_result) in h_results.chunks(glwe_size).enumerate() {
            let glwe_result = GlweCiphertext::from_container(h_result, polynomial_size);

            let mut decrypted_result =
                PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
            rlwe_sk.decrypt_glwe(&mut decrypted_result, &glwe_result);
            let lut_number = (((*decrypted_result.tensor.first() as f64)
                / (1u64 << delta_log) as f64)
                .round() as u64)
                % (1 << (64 - delta_log));

            println!("\nTree {})", i);
            println!("result: {:?}", decrypted_result.tensor.first());
            // println!("\nresult: {:?}", decrypted_result.tensor.as_container());
            let tree_offset = i as u64;
            let witness = (base_witness + tree_offset) % (1 << (64 - delta_log));
            println!("witness : {:?}", witness);
            println!("lut_number: {}", lut_number);
            assert_eq!(lut_number, witness);
        }
        println!("Done!");
    }
}

#[test]
pub fn test_cuda_extract_bits() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(585);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(7);

    let level_ksk = DecompositionLevelCount(2);
    let base_log_ksk = DecompositionBaseLog(11);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let number_of_bits_of_message_including_padding = 5_usize;
    // Tests take about 2-3 seconds on a laptop with this number
    let nos: u32 = 1;
    let number_of_test_runs = 10;

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut coef_bsk = StandardBootstrapKey::allocate(
        0_u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_small_sk, &rlwe_sk, std, &mut encryption_generator);

    /*
    // allocation for the bootstrapping key
    let mut fourier_bsk: FourierBootstrapKey<_, u64> = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    */

    let mut h_coef_bsk: Vec<u64> = vec![];
    let mut h_ksk: Vec<u64> = vec![];
    h_coef_bsk.append(&mut coef_bsk.tensor.as_slice().to_vec());
    let gpu_index = GpuIndex(0);
    let stream = CudaStream::new(gpu_index).unwrap();

    let bsk_size = (glwe_dimension.0 + 1)
        * (glwe_dimension.0 + 1)
        * polynomial_size.0
        * level_bsk.0
        * lwe_dimension.0;
    let ksksize = level_ksk.0 * polynomial_size.0 * (lwe_dimension.0 + 1);

    let mut h_lut_vector_indexes = vec![0 as u32; 1];

    let mut d_lwe_array_out = stream.malloc::<u64>(
        nos * (lwe_dimension.0 as u32 + 1) * (number_of_bits_of_message_including_padding) as u32,
    );
    let mut d_lwe_array_in = stream.malloc::<u64>(nos * (polynomial_size.0 + 1) as u32);
    let mut d_lwe_array_in_buffer = stream.malloc::<u64>(nos * (polynomial_size.0 + 1) as u32);
    let mut d_lwe_array_in_shifted_buffer =
        stream.malloc::<u64>(nos * (polynomial_size.0 + 1) as u32);
    let mut d_lwe_array_out_ks_buffer = stream.malloc::<u64>(nos * (lwe_dimension.0 + 1) as u32);
    let mut d_lwe_array_out_pbs_buffer = stream.malloc::<u64>(nos * (polynomial_size.0 + 1) as u32);
    let mut d_lut_pbs = stream.malloc::<u64>((2 * polynomial_size.0) as u32);
    let mut d_lut_vector_indexes = stream.malloc::<u32>(1);
    let mut d_ksk = stream.malloc::<u64>(ksksize as u32);
    let mut d_bsk_fourier = stream.malloc::<f64>(bsk_size as u32);
    //decomp_size.0 * (output_size.0 + 1) * input_size.0
    unsafe {
        cuda_initialize_twiddles(polynomial_size.0 as u32, gpu_index.0 as u32);
        cuda_convert_lwe_bootstrap_key_64(
            d_bsk_fourier.as_mut_c_ptr(),
            h_coef_bsk.as_ptr() as *mut c_void,
            stream.stream_handle().0,
            gpu_index.0 as u32,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            level_bsk.0 as u32,
            polynomial_size.0 as u32,
        );
        stream.copy_to_gpu::<u32>(&mut d_lut_vector_indexes, &mut h_lut_vector_indexes);
    }
    //let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(),
    // fourier_bsk.glwe_size()); fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

    let lwe_big_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0_u64,
        level_ksk,
        base_log_ksk,
        lwe_big_sk.key_size(),
        lwe_small_sk.key_size(),
    );
    ksk_lwe_big_to_small.fill_with_keyswitch_key(
        &lwe_big_sk,
        &lwe_small_sk,
        std,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(64 - number_of_bits_of_message_including_padding);
    // Decomposer to manage the rounding after decrypting the extracted bit

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));

    h_ksk.clone_from(&ksk_lwe_big_to_small.into_container());

    ////////////////////////////////////////////////////////////////////////////////////////////////

    use std::time::Instant;
    let mut now = Instant::now();
    let mut elapsed = now.elapsed();

    for _ in 0..number_of_test_runs {
        // Generate a random plaintext in [0; 2^{number_of_bits_of_message_including_padding}[
        let val = test_tools::random_uint_between(
            0..2u64.pow(number_of_bits_of_message_including_padding as u32),
        );

        // Encryption
        let message = Plaintext(val << delta_log.0);
        println!("{:?}", message);
        let mut lwe_array_in = LweCiphertext::allocate(0u64, LweSize(polynomial_size.0 + 1));
        lwe_big_sk.encrypt_lwe(&mut lwe_array_in, &message, std, &mut encryption_generator);

        // Bit extraction
        // Extract all the bits
        let number_values_to_extract = ExtractedBitsCount(64 - delta_log.0);

        let mut _lwe_array_out_list = LweList::allocate(
            0u64,
            lwe_dimension.to_lwe_size(),
            CiphertextCount(number_values_to_extract.0),
        );
        /*
        extract_bits(
            delta_log,
            &mut lwe_array_out_list,
            &lwe_array_in,
            &ksk_lwe_big_to_small,
            &fourier_bsk,
            &mut buffers,
            number_values_to_extract,
        );
        */

        unsafe {
            stream.copy_to_gpu::<u64>(&mut d_ksk, &mut h_ksk);
            //println!("rust_lwe_array_in: {:?}", lwe_array_in);
            stream.copy_to_gpu::<u64>(&mut d_lwe_array_in, &mut lwe_array_in.tensor.as_slice());

            now = Instant::now();
            cuda_extract_bits_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_lwe_array_out.as_mut_c_ptr(),
                d_lwe_array_in.as_c_ptr(),
                d_lwe_array_in_buffer.as_mut_c_ptr(),
                d_lwe_array_in_shifted_buffer.as_mut_c_ptr(),
                d_lwe_array_out_ks_buffer.as_mut_c_ptr(),
                d_lwe_array_out_pbs_buffer.as_mut_c_ptr(),
                d_lut_pbs.as_mut_c_ptr(),
                d_lut_vector_indexes.as_mut_c_ptr(),
                d_ksk.as_c_ptr(),
                d_bsk_fourier.as_c_ptr(),
                number_values_to_extract.0 as u32,
                delta_log.0 as u32,
                polynomial_size.0 as u32,
                lwe_dimension.0 as u32,
                glwe_dimension.0 as u32,
                base_log_bsk.0 as u32,
                level_bsk.0 as u32,
                base_log_ksk.0 as u32,
                level_ksk.0 as u32,
                nos,
                stream.get_max_shared_memory().unwrap() as u32,
            );
            elapsed += now.elapsed();
            println!("elapsed: {:?}", elapsed);

            let mut h_result = vec![0u64; (lwe_dimension.0 + 1) * number_values_to_extract.0];
            stream.copy_to_cpu::<u64>(&mut h_result, &d_lwe_array_out);

            cuda_synchronize_device(gpu_index.0 as u32);

            let mut i = 0;
            for result_h in h_result.chunks(lwe_dimension.0 + 1).rev() {
                let result_ct = LweCiphertext::from_container(result_h);
                let mut decrypted_message = Plaintext(0_u64);
                lwe_small_sk.decrypt_lwe(&mut decrypted_message, &result_ct);
                // Round after decryption using decomposer
                let decrypted_rounded = decomposer.closest_representable(decrypted_message.0);
                // Bring back the extracted bit found in the MSB in the LSB
                let decrypted_extract_bit = decrypted_rounded >> 63;
                println!("extracted bit : {:?}", decrypted_extract_bit);
                println!("{:?}", decrypted_message);

                // TODO decomposition algorithm should be changed for keyswitch and amortized pbs.

                assert_eq!(
                    ((message.0 >> delta_log.0) >> i) & 1,
                    decrypted_extract_bit,
                    "Bit #{}, for plaintext {:#066b}",
                    delta_log.0 + i,
                    message.0
                );

                i += 1;
            }
        }
    }
    println!("number of tests: {}", number_of_test_runs);
    println!("total_time: {:?}", elapsed);
    println!("average  time {:?}", elapsed / number_of_test_runs);
}

// Circuit bootstrap + vertical packing applying an identity lut
#[test]
pub fn test_extract_bit_circuit_bootstrapping_cuda_vertical_packing() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);
    //decomp_size.0 * (output_size.0 + 1) * input_size.0
    unsafe {
        cuda_initialize_twiddles(polynomial_size.0 as u32, 0u32);
    }

    // Value was 0.000_000_000_000_000_221_486_881_160_055_68_513645324585951
    // But rust indicates it gets truncated anyways to
    // 0.000_000_000_000_000_221_486_881_160_055_68
    let std_small = StandardDev::from_standard_dev(0.000_000_000_000_000_221_486_881_160_055_68);
    // Value was 0.000_061_200_133_780_220_371_345
    // But rust indicates it gets truncated anyways to
    // 0.000_061_200_133_780_220_36
    let std_big = StandardDev::from_standard_dev(0.000_061_200_133_780_220_36);

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    //create GLWE and LWE secret key
    let glwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let lwe_big_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(
        &lwe_small_sk,
        &glwe_sk,
        Variance(std_small.get_variance()),
        &mut encryption_generator,
    );
    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        vec![
            c64::default();
            lwe_dimension.0 * polynomial_size.0 / 2
                * level_bsk.0
                * glwe_dimension.to_glwe_size().0
                * glwe_dimension.to_glwe_size().0
        ],
        lwe_dimension,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        base_log_bsk,
        level_bsk,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut mem = GlobalMemBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
    fourier_bsk.as_mut_view().fill_with_forward_fourier(
        coef_bsk.as_view(),
        fft,
        DynStack::new(&mut mem),
    );

    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0u64,
        level_ksk,
        base_log_ksk,
        lwe_big_sk.key_size(),
        lwe_small_sk.key_size(),
    );
    ksk_lwe_big_to_small.fill_with_keyswitch_key(
        &lwe_big_sk,
        &lwe_small_sk,
        Variance(std_big.get_variance()),
        &mut encryption_generator,
    );

    // Creation of all the pfksk for the circuit bootstrapping
    let mut vec_fpksk = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
        0u64,
        level_pksk,
        base_log_pksk,
        lwe_big_sk.key_size(),
        glwe_sk.key_size(),
        glwe_sk.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(glwe_dimension.to_glwe_size().0),
    );

    vec_fpksk.par_fill_with_fpksk_for_circuit_bootstrap(
        &lwe_big_sk,
        &glwe_sk,
        std_small,
        &mut encryption_generator,
    );

    let number_of_bits_in_input_lwe = 10;
    let number_of_values_to_extract = ExtractedBitsCount(number_of_bits_in_input_lwe);

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(10), DecompositionLevelCount(1));

    // Here even thought the deltas have the same value, they can differ between ciphertexts and lut
    // so keeping both separate
    let delta_log = DeltaLog(64 - number_of_values_to_extract.0);
    let delta_lut = DeltaLog(64 - number_of_values_to_extract.0);

    let number_of_test_runs = 1;

    for run_number in 0..number_of_test_runs {
        let cleartext =
            test_tools::random_uint_between(0..2u64.pow(number_of_bits_in_input_lwe as u32));

        println!("{}", cleartext);

        let message = Plaintext(cleartext << delta_log.0);
        let mut lwe_in =
            LweCiphertext::allocate(0u64, LweSize(glwe_dimension.0 * polynomial_size.0 + 1));
        lwe_big_sk.encrypt_lwe(
            &mut lwe_in,
            &message,
            Variance(std_big.get_variance()),
            &mut encryption_generator,
        );
        let mut extracted_bits_lwe_list = LweList::allocate(
            0u64,
            ksk_lwe_big_to_small.lwe_size(),
            CiphertextCount(number_of_values_to_extract.0),
        );

        let mut mem = GlobalMemBuffer::new(
            extract_bits_scratch::<u64>(
                lwe_dimension,
                ksk_lwe_big_to_small.after_key_size(),
                fourier_bsk.glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        );
        extract_bits(
            extracted_bits_lwe_list.as_mut_view(),
            lwe_in.as_view(),
            ksk_lwe_big_to_small.as_view(),
            fourier_bsk.as_view(),
            delta_log,
            number_of_values_to_extract,
            fft,
            DynStack::new(&mut mem),
        );

        // Decrypt all extracted bit for checking purposes in case of problems
        for ct in extracted_bits_lwe_list.ciphertext_iter() {
            let mut decrypted_message = Plaintext(0u64);
            lwe_small_sk.decrypt_lwe(&mut decrypted_message, &ct);
            let extract_bit_result =
                (((decrypted_message.0 as f64) / (1u64 << (63)) as f64).round()) as u64;
            println!("{:?}", extract_bit_result);
            println!("{:?}", decrypted_message);
        }

        // LUT creation
        let number_of_luts_and_output_vp_ciphertexts = 1;
        let mut lut_size = polynomial_size.0;

        let lut_poly_list = if run_number % 2 == 0 {
            // Test with a small lut, only triggering a blind rotate
            if lut_size < (1 << extracted_bits_lwe_list.count().0) {
                lut_size = 1 << extracted_bits_lwe_list.count().0;
            }
            let mut lut = Vec::with_capacity(lut_size);

            for i in 0..lut_size {
                lut.push((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }

            // Here we have a single lut, so store it directly in the polynomial list
            PolynomialList::from_container(lut, PolynomialSize(lut_size))
        } else {
            // Test with a big lut, triggering an actual cmux tree
            let mut lut_poly_list = PolynomialList::allocate(
                0u64,
                PolynomialCount(1 << number_of_bits_in_input_lwe),
                polynomial_size,
            );
            for (i, mut polynomial) in lut_poly_list.polynomial_iter_mut().enumerate() {
                polynomial
                    .as_mut_tensor()
                    .fill_with_element((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }
            lut_poly_list
        };

        // We need as many output ciphertexts as we have input luts
        let mut vertical_packing_lwe_list_out = LweList::allocate(
            0u64,
            LweDimension(polynomial_size.0 * glwe_dimension.0).to_lwe_size(),
            CiphertextCount(number_of_luts_and_output_vp_ciphertexts),
        );

        // Perform circuit bootstrap + vertical packing
        let mut mem = GlobalMemBuffer::new(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                extracted_bits_lwe_list.count(),
                vertical_packing_lwe_list_out.count(),
                extracted_bits_lwe_list.lwe_size(),
                lut_poly_list.polynomial_count(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                vec_fpksk.output_polynomial_size(),
                fourier_bsk.glwe_size(),
                level_cbs,
                fft,
            )
            .unwrap(),
        );
        circuit_bootstrap_boolean_cuda_vertical_packing(
            lut_poly_list.as_view(),
            fourier_bsk.as_view(),
            vertical_packing_lwe_list_out.as_mut_view(),
            extracted_bits_lwe_list.as_view(),
            vec_fpksk.as_view(),
            level_cbs,
            base_log_cbs,
            fft,
            DynStack::new(&mut mem),
        );

        // We have a single output ct
        let result_ct = vertical_packing_lwe_list_out
            .ciphertext_iter()
            .next()
            .unwrap();

        // decrypt result
        let mut decrypted_message = Plaintext(0u64);
        let lwe_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result_ct);
        let decoded_message = decomposer.closest_representable(decrypted_message.0) >> delta_log.0;

        // print information if the result is wrong
        if decoded_message != cleartext {
            panic!(
                "decoded_message ({:?}) != cleartext ({:?})\n\
                decrypted_message: {:?}, decoded_message: {:?}",
                decoded_message, cleartext, decrypted_message, decoded_message
            );
        }
        println!("{:?}", decoded_message);
    }
}

#[test]
pub fn test_extract_bit_cuda_circuit_bootstrapping_vertical_packing() {
    // define settings
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);

    // Value was 0.000_000_000_000_000_221_486_881_160_055_68_513645324585951
    // But rust indicates it gets truncated anyways to
    // 0.000_000_000_000_000_221_486_881_160_055_68
    let std_small = StandardDev::from_standard_dev(0.000_000_000_000_000_221_486_881_160_055_68);
    // Value was 0.000_061_200_133_780_220_371_345
    // But rust indicates it gets truncated anyways to
    // 0.000_061_200_133_780_220_36
    let std_big = StandardDev::from_standard_dev(0.000_061_200_133_780_220_36);

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    let number_of_test_runs = 2;

    for tau in 1..=2 {
        let p = 10 / tau;
        for run_number in 0..number_of_test_runs {
            // When log_2_poly_size == 10 the VP skips the cmux tree.
            // When log_2_poly_size == 9 we have a cmux tree done with a single cmux.
            let log_2_poly_size = if run_number % 2 == 0 { 10 } else { 9 };
            let polynomial_size = PolynomialSize(1 << log_2_poly_size);

            println!("\npolynomial_size: {}", polynomial_size.0);

            unsafe {
                cuda_initialize_twiddles(polynomial_size.0 as u32, 0u32);
            }
            //create GLWE and LWE secret key
            let glwe_sk: GlweSecretKey<_, Vec<u64>> = GlweSecretKey::generate_binary(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );
            let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
                LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

            let lwe_big_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());

            // allocation and generation of the key in coef domain:
            let mut coef_bsk = StandardBootstrapKey::allocate(
                0u64,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                level_bsk,
                base_log_bsk,
                lwe_dimension,
            );
            coef_bsk.fill_with_new_key(
                &lwe_small_sk,
                &glwe_sk,
                Variance(std_small.get_variance()),
                &mut encryption_generator,
            );

            // allocation for the bootstrapping key
            let mut fourier_bsk = FourierLweBootstrapKey::new(
                vec![
                    c64::default();
                    lwe_dimension.0 * polynomial_size.0 / 2
                        * level_bsk.0
                        * glwe_dimension.to_glwe_size().0
                        * glwe_dimension.to_glwe_size().0
                ],
                lwe_dimension,
                polynomial_size,
                glwe_dimension.to_glwe_size(),
                base_log_bsk,
                level_bsk,
            );

            let fft = Fft::new(polynomial_size);
            let fft = fft.as_view();

            let mut mem = GlobalMemBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
            fourier_bsk.as_mut_view().fill_with_forward_fourier(
                coef_bsk.as_view(),
                fft,
                DynStack::new(&mut mem),
            );
            let mut cuda_engine = CudaEngine::new(()).unwrap();
            let d_fourier_bsk = cuda_engine
                .convert_lwe_bootstrap_key(&LweBootstrapKey64(coef_bsk))
                .unwrap();

            let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
                0u64,
                level_ksk,
                base_log_ksk,
                lwe_big_sk.key_size(),
                lwe_small_sk.key_size(),
            );
            ksk_lwe_big_to_small.fill_with_keyswitch_key(
                &lwe_big_sk,
                &lwe_small_sk,
                Variance(std_big.get_variance()),
                &mut encryption_generator,
            );

            // Creation of all the pfksk for the circuit bootstrapping
            let mut vec_fpksk = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
                0u64,
                level_pksk,
                base_log_pksk,
                lwe_big_sk.key_size(),
                glwe_sk.key_size(),
                glwe_sk.polynomial_size(),
                FunctionalPackingKeyswitchKeyCount(glwe_dimension.to_glwe_size().0),
            );

            vec_fpksk.par_fill_with_fpksk_for_circuit_bootstrap(
                &lwe_big_sk,
                &glwe_sk,
                std_small,
                &mut encryption_generator,
            );
            let d_vec_fpksk = cuda_engine
                .convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
                    &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(vec_fpksk.clone()),
                )
                .unwrap();

            // Here even thought the deltas have the same value, they can differ between ciphertexts
            // and lut so keeping both separate
            let number_of_values_to_extract = ExtractedBitsCount(p as usize);
            let delta_log = DeltaLog(64 - number_of_values_to_extract.0);
            let delta_lut = DeltaLog(64 - number_of_values_to_extract.0);
            let number_of_cleartext_runs = 10;

            for _cleartext_number in 0..number_of_cleartext_runs {
                let mut vec_cleartext = vec![];
                let mut vec_cleartext_delta_log = vec![];
                for _i in 0..tau {
                    let x = test_tools::random_uint_between(0..2u64.pow(p as u32));
                    // let x = 42u64;
                    vec_cleartext.push(x);
                    vec_cleartext_delta_log.push(x << delta_log.0);
                }

                println!("{:?}", vec_cleartext);

                let message = PlaintextList::from_container(vec_cleartext_delta_log);
                let mut lwe_in_list = LweList::allocate(
                    0u64,
                    LweSize(glwe_dimension.0 * polynomial_size.0 + 1),
                    CiphertextCount(tau),
                );
                lwe_big_sk.encrypt_lwe_list(
                    &mut lwe_in_list,
                    &message,
                    Variance(std_big.get_variance()),
                    &mut encryption_generator,
                );
                let mut extracted_bits_lwe_list = LweList::allocate(
                    0u64,
                    ksk_lwe_big_to_small.lwe_size(),
                    CiphertextCount(tau * number_of_values_to_extract.0),
                );

                let decomposer =
                    SignedDecomposer::new(DecompositionBaseLog(10), DecompositionLevelCount(1));

                let mut mem = GlobalMemBuffer::new(
                    extract_bits_scratch::<u64>(
                        lwe_dimension,
                        ksk_lwe_big_to_small.after_key_size(),
                        fourier_bsk.glwe_size(),
                        polynomial_size,
                        fft,
                    )
                    .unwrap(),
                );
                for (lwe_out, lwe_in) in izip!(
                    extracted_bits_lwe_list
                        .as_mut_view()
                        .sublist_iter_mut(CiphertextCount(number_of_values_to_extract.0)),
                    lwe_in_list.as_view().ciphertext_iter()
                ) {
                    extract_bits(
                        lwe_out,
                        lwe_in,
                        ksk_lwe_big_to_small.as_view(),
                        fourier_bsk.as_view(),
                        delta_log,
                        number_of_values_to_extract,
                        fft,
                        DynStack::new(&mut mem),
                    );
                }

                // Decrypt all extracted bit for checking purposes in case of problems
                for (i, ct) in extracted_bits_lwe_list.ciphertext_iter().enumerate() {
                    let message: u64 = vec_cleartext[i / number_of_values_to_extract.0];
                    let bit_idx: u64 = (number_of_values_to_extract.0
                        - (i % number_of_values_to_extract.0)
                        - 1) as u64;
                    let mut decrypted_message = Plaintext(0u64);
                    lwe_small_sk.decrypt_lwe(&mut decrypted_message, &ct);
                    let extract_bit_result =
                        (((decrypted_message.0 as f64) / (1u64 << (63)) as f64).round()) as u64;
                    println!(
                        "{}) Extracted: {:?}, Expected: {:?}",
                        i,
                        extract_bit_result % 2,
                        (message >> bit_idx) & 1
                    );
                }

                println!(
                    "number_of_values_to_extract (p): {}",
                    number_of_values_to_extract.0
                );
                println!("tau * p: {}", extracted_bits_lwe_list.count().0);

                let d_lwe_array = cuda_engine
                    .convert_lwe_ciphertext_vector(&LweCiphertextVector64(
                        extracted_bits_lwe_list.clone(),
                    ))
                    .unwrap();

                // LUT creation
                let mut lut_size = polynomial_size.0;
                let mut lut_num = tau << (tau * p - polynomial_size.log2().0); // r

                println!("lut_num: {}", lut_num);

                let mut big_lut = Vec::with_capacity(lut_num * lut_size);
                for i in (0..tau).rev() {
                    let mut small_lut = Vec::with_capacity(lut_size);
                    for value in 0..(1 << (tau * p)) {
                        let nbits = i * p;
                        let x = (value >> nbits) & ((1 << p) - 1);
                        small_lut.push((x as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
                    }
                    big_lut.extend(small_lut);
                }
                // big_lut.truncate(lut_num * lut_size);
                assert_eq!(big_lut.len(), lut_num * lut_size);
                let lut_poly_list =
                    PolynomialList::from_container(big_lut, PolynomialSize(lut_size));
                println!(
                    "lut_poly_list length (2^p): {}",
                    lut_poly_list.polynomial_count().0
                );
                const UNSAFE_SECRET: u128 = 0;
                let mut default_engine =
                    DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET))).unwrap();
                let lut_vector = default_engine
                    .create_plaintext_vector_from(&lut_poly_list.into_container())
                    .unwrap();
                let d_lut_vector = cuda_engine.convert_plaintext_vector(&lut_vector).unwrap();

                // We need as many output ciphertexts as we have input luts
                let vertical_packing_lwe_list_out = LweList::allocate(
                    0u64,
                    LweDimension(polynomial_size.0 * glwe_dimension.0).to_lwe_size(),
                    CiphertextCount(tau),
                );
                let mut d_lwe_array_out = cuda_engine
                    .convert_lwe_ciphertext_vector(
                        &(LweCiphertextVector64(vertical_packing_lwe_list_out)),
                    )
                    .unwrap();

                unsafe {
                    execute_circuit_bootstrap_vertical_packing_on_gpu::<u64>(
                        cuda_engine.get_cuda_streams(),
                        &mut d_lwe_array_out.0,
                        &d_lwe_array.0,
                        &d_lut_vector.0,
                        &d_fourier_bsk.0,
                        &d_vec_fpksk.0,
                        level_cbs,
                        base_log_cbs,
                        cuda_engine.get_cuda_shared_memory(),
                    );
                }

                let vertical_packing_lwe_list_out = cuda_engine
                    .convert_lwe_ciphertext_vector(&d_lwe_array_out)
                    .unwrap()
                    .0;

                // decrypt result
                let mut decrypted_messages = PlaintextList::allocate(0u64, PlaintextCount(tau));
                let lwe_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());
                lwe_sk.decrypt_lwe_list(&mut decrypted_messages, &vertical_packing_lwe_list_out);
                let mut decoded_messages = vec![];

                for message in decrypted_messages.plaintext_iter() {
                    let decoded_message =
                        decomposer.closest_representable(message.0) >> delta_log.0;
                    decoded_messages.push(decoded_message);
                }

                // print information if the result is wrong
                if decoded_messages != vec_cleartext {
                    panic!(
                        "decoded_message ({:?}) != cleartext ({:?})\n\
                        decrypted_message: {:?}, decoded_message: {:?}",
                        decoded_messages, vec_cleartext, decrypted_messages, decoded_messages
                    );
                }
                println!("{:?}\n", decoded_messages);
            }
        }
    }
}

#[test]
pub fn test_cuda_wop_pbs() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);
    //decomp_size.0 * (output_size.0 + 1) * input_size.0
    unsafe {
        cuda_initialize_twiddles(polynomial_size.0 as u32, 0u32);
    }

    // Value was 0.000_000_000_000_000_221_486_881_160_055_68_513645324585951
    // But rust indicates it gets truncated anyways to
    // 0.000_000_000_000_000_221_486_881_160_055_68
    let std_small = StandardDev::from_standard_dev(0.000_000_000_000_000_221_486_881_160_055_68);
    // Value was 0.000_061_200_133_780_220_371_345
    // But rust indicates it gets truncated anyways to
    // 0.000_061_200_133_780_220_36
    let std_big = StandardDev::from_standard_dev(0.000_061_200_133_780_220_36);

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    //create GLWE and LWE secret key
    let glwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let lwe_big_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(
        &lwe_small_sk,
        &glwe_sk,
        Variance(std_small.get_variance()),
        &mut encryption_generator,
    );
    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        vec![
            c64::default();
            lwe_dimension.0 * polynomial_size.0 / 2
                * level_bsk.0
                * glwe_dimension.to_glwe_size().0
                * glwe_dimension.to_glwe_size().0
        ],
        lwe_dimension,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        base_log_bsk,
        level_bsk,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut mem = GlobalMemBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
    fourier_bsk.as_mut_view().fill_with_forward_fourier(
        coef_bsk.as_view(),
        fft,
        DynStack::new(&mut mem),
    );
    let mut cuda_engine = CudaEngine::new(()).unwrap();
    let d_fourier_bsk = cuda_engine
        .convert_lwe_bootstrap_key(&LweBootstrapKey64(coef_bsk))
        .unwrap();

    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0u64,
        level_ksk,
        base_log_ksk,
        lwe_big_sk.key_size(),
        lwe_small_sk.key_size(),
    );
    ksk_lwe_big_to_small.fill_with_keyswitch_key(
        &lwe_big_sk,
        &lwe_small_sk,
        Variance(std_big.get_variance()),
        &mut encryption_generator,
    );
    let d_ksk = cuda_engine
        .convert_lwe_keyswitch_key(&LweKeyswitchKey64(ksk_lwe_big_to_small.clone()))
        .unwrap();

    // Creation of all the pfksk for the circuit bootstrapping
    let mut vec_fpksk = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
        0u64,
        level_pksk,
        base_log_pksk,
        lwe_big_sk.key_size(),
        glwe_sk.key_size(),
        glwe_sk.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(glwe_dimension.to_glwe_size().0),
    );

    vec_fpksk.par_fill_with_fpksk_for_circuit_bootstrap(
        &lwe_big_sk,
        &glwe_sk,
        std_small,
        &mut encryption_generator,
    );
    let d_vec_fpksk = cuda_engine
        .convert_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
            &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(vec_fpksk.clone()),
        )
        .unwrap();

    let number_of_bits_in_input_lwe = 10;
    let number_of_values_to_extract = ExtractedBitsCount(number_of_bits_in_input_lwe);

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(10), DecompositionLevelCount(1));

    // Here even thought the deltas have the same value, they can differ between ciphertexts and lut
    // so keeping both separate
    let delta_log = DeltaLog(64 - number_of_values_to_extract.0);
    let delta_lut = DeltaLog(64 - number_of_values_to_extract.0);

    let number_of_test_runs = 1;

    for run_number in 0..number_of_test_runs {
        let cleartext =
            test_tools::random_uint_between(0..2u64.pow(number_of_bits_in_input_lwe as u32));

        println!("{}", cleartext);

        let message = PlaintextList::from_container(vec![cleartext << delta_log.0; 1]);
        let mut lwe_in = LweList::allocate(
            0u64,
            LweSize(glwe_dimension.0 * polynomial_size.0 + 1),
            CiphertextCount(1),
        );
        lwe_big_sk.encrypt_lwe_list(
            &mut lwe_in,
            &message,
            Variance(std_big.get_variance()),
            &mut encryption_generator,
        );
        let d_lwe_array_in = cuda_engine
            .convert_lwe_ciphertext_vector(&LweCiphertextVector64(lwe_in.clone()))
            .unwrap();
        let extracted_bits_lwe_list = LweList::allocate(
            0u64,
            ksk_lwe_big_to_small.lwe_size(),
            CiphertextCount(number_of_values_to_extract.0),
        );

        // LUT creation
        let number_of_luts_and_output_vp_ciphertexts = 1;
        let mut lut_size = polynomial_size.0;

        let lut_poly_list = if run_number % 2 == 0 {
            // Test with a small lut, only triggering a blind rotate
            if lut_size < (1 << extracted_bits_lwe_list.count().0) {
                lut_size = 1 << extracted_bits_lwe_list.count().0;
            }
            let mut lut = Vec::with_capacity(lut_size);

            for i in 0..lut_size {
                lut.push((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }

            // Here we have a single lut, so store it directly in the polynomial list
            PolynomialList::from_container(lut, PolynomialSize(lut_size))
        } else {
            // Test with a big lut, triggering an actual cmux tree
            let mut lut_poly_list = PolynomialList::allocate(
                0u64,
                PolynomialCount(1 << number_of_bits_in_input_lwe),
                polynomial_size,
            );
            for (i, mut polynomial) in lut_poly_list.polynomial_iter_mut().enumerate() {
                polynomial
                    .as_mut_tensor()
                    .fill_with_element((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }
            lut_poly_list
        };
        const UNSAFE_SECRET: u128 = 0;
        let mut default_engine =
            DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET))).unwrap();
        let lut_vector = default_engine
            .create_plaintext_vector_from(&lut_poly_list.into_container())
            .unwrap();
        let d_lut_vector = cuda_engine.convert_plaintext_vector(&lut_vector).unwrap();

        // We need as many output ciphertexts as we have input luts
        let vertical_packing_lwe_list_out = LweList::allocate(
            0u64,
            LweDimension(polynomial_size.0 * glwe_dimension.0).to_lwe_size(),
            CiphertextCount(number_of_luts_and_output_vp_ciphertexts),
        );

        let mut d_lwe_array_out = cuda_engine
            .convert_lwe_ciphertext_vector(&(LweCiphertextVector64(vertical_packing_lwe_list_out)))
            .unwrap();

        unsafe {
            cuda_wop_pbs_64(
                cuda_engine
                    .get_cuda_streams()
                    .get(0)
                    .unwrap()
                    .stream_handle()
                    .0,
                0,
                d_lwe_array_out.0.d_vecs[0].as_mut_c_ptr(),
                d_lwe_array_in.0.d_vecs[0].as_c_ptr(),
                d_lut_vector.0.d_vecs[0].as_c_ptr(),
                d_fourier_bsk.0.d_vecs[0].as_c_ptr(),
                d_ksk.0.d_vecs[0].as_c_ptr(),
                d_vec_fpksk.0.d_vecs[0].as_c_ptr(),
                glwe_dimension.0 as u32,
                lwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log_bsk.0 as u32,
                level_bsk.0 as u32,
                base_log_ksk.0 as u32,
                level_ksk.0 as u32,
                base_log_pksk.0 as u32,
                level_pksk.0 as u32,
                base_log_cbs.0 as u32,
                level_cbs.0 as u32,
                number_of_bits_in_input_lwe as u32,
                number_of_bits_in_input_lwe as u32,
                1,
                cuda_engine.get_cuda_shared_memory().0 as u32,
            );
        }
        let vertical_packing_lwe_list_out = cuda_engine
            .convert_lwe_ciphertext_vector(&d_lwe_array_out)
            .unwrap()
            .0;

        // We have a single output ct
        let result_ct = vertical_packing_lwe_list_out
            .ciphertext_iter()
            .next()
            .unwrap();

        // decrypt result
        let mut decrypted_message = Plaintext(0u64);
        let lwe_sk = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result_ct);
        let decoded_message = decomposer.closest_representable(decrypted_message.0) >> delta_log.0;

        // print information if the result is wrong
        if decoded_message != cleartext {
            panic!(
                "decoded_message ({:?}) != cleartext ({:?})\n\
                decrypted_message: {:?}, decoded_message: {:?}",
                decoded_message, cleartext, decrypted_message, decoded_message
            );
        }
        println!("{:?}", decoded_message);
    }
}

// Test the circuit bootstrapping with private functional ks
// Verify the decryption has the expected content
#[test]
fn test_cuda_circuit_bootstrapping_binary() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(10);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(11);

    let level_pksk = DecompositionLevelCount(2);
    let base_log_pksk = DecompositionBaseLog(15);

    let level_count_cbs = DecompositionLevelCount(1);
    let base_log_cbs = DecompositionBaseLog(10);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    // Create GLWE and LWE secret key
    let glwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    // Allocation and generation of the bootstrap key in standard domain:
    let mut std_bsk = StandardBootstrapKey::allocate(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    std_bsk.fill_with_new_key(&lwe_sk, &glwe_sk, std, &mut encryption_generator);

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        vec![
            c64::default();
            lwe_dimension.0 * polynomial_size.0 / 2
                * level_bsk.0
                * glwe_dimension.to_glwe_size().0
                * glwe_dimension.to_glwe_size().0
        ],
        lwe_dimension,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        base_log_bsk,
        level_bsk,
    );

    // get gpu index and initialize stream
    let gpu_index = GpuIndex(0);
    let stream = CudaStream::new(gpu_index).unwrap();

    // number of samples
    let nos: u32 = 1;

    let bsk_size = (glwe_dimension.0 + 1)
        * (glwe_dimension.0 + 1)
        * polynomial_size.0
        * level_bsk.0
        * lwe_dimension.0;

    // host pointer for bsk coef
    let mut h_coef_bsk: Vec<u64> = vec![];
    // device pointer for fourier bsk
    let mut d_bsk_fourier = stream.malloc::<f64>(bsk_size as u32);
    // use same bsk coefficients for gpu bsk
    h_coef_bsk.append(&mut std_bsk.tensor.as_slice().to_vec());
    // convert bsk coefficients to fourier on device
    unsafe {
        cuda_initialize_twiddles(polynomial_size.0 as u32, gpu_index.0 as u32);
        cuda_convert_lwe_bootstrap_key_64(
            d_bsk_fourier.as_mut_c_ptr(),
            h_coef_bsk.as_ptr() as *mut c_void,
            stream.stream_handle().0,
            gpu_index.0 as u32,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            level_bsk.0 as u32,
            polynomial_size.0 as u32,
        );
    }

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut mem = GlobalMemBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
    let stack = DynStack::new(&mut mem);
    fourier_bsk
        .as_mut_view()
        .fill_with_forward_fourier(std_bsk.as_view(), fft, stack);

    let lwe_sk_bs_output = LweSecretKey::binary_from_container(glwe_sk.as_tensor().as_slice());

    // Creation of all the pfksk for the circuit bootstrapping
    let mut vec_pfksk = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
        0u64,
        level_pksk,
        base_log_pksk,
        lwe_sk_bs_output.key_size(),
        glwe_sk.key_size(),
        glwe_sk.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(glwe_dimension.to_glwe_size().0),
    );

    vec_pfksk.par_fill_with_fpksk_for_circuit_bootstrap(
        &lwe_sk_bs_output,
        &glwe_sk,
        std,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(60);

    // value is 0 or 1 as CBS works on messages expected to contain 1 bit of information
    let value: u64 = test_tools::random_uint_between(0..2u64);
    // Encryption of an LWE with the value 'message'
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    let mut cbs_res = StandardGgswCiphertext::allocate(
        0u64,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        level_count_cbs,
        base_log_cbs,
    );

    let mut mem = GlobalMemBuffer::new(
        circuit_bootstrap_boolean_scratch::<u64>(
            lwe_in.lwe_size(),
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            fft,
        )
        .unwrap(),
    );
    let stack = DynStack::new(&mut mem);
    // Execute the CBS
    //println!("vec_pfksk: {:?}", vec_pfksk);
    circuit_bootstrap_boolean(
        fourier_bsk.as_view(),
        lwe_in.as_view(),
        cbs_res.as_mut_view(),
        delta_log,
        vec_pfksk.as_view(),
        fft,
        stack,
    );

    let mut h_lut_vector_indexes: Vec<u32> = vec![0 as u32; nos as usize * level_count_cbs.0];

    for index in 0..nos as usize * level_count_cbs.0 {
        h_lut_vector_indexes[index] = index as u32 % level_count_cbs.0 as u32;
    }

    // allocate and initialize device pointers for circuit bootstrap
    // output glwe array for fp-ks
    let mut d_ggsw_out = stream.malloc::<u64>(
        nos * level_count_cbs.0 as u32
            * (glwe_dimension.0 as u32 + 1)
            * (glwe_dimension.0 as u32 + 1)
            * polynomial_size.0 as u32,
    );
    // input lwe array for fp-ks
    let mut d_lwe_array_in_fp_ks_buffer = stream.malloc::<u64>(
        nos * level_count_cbs.0 as u32
            * (glwe_dimension.0 as u32 + 1)
            * (polynomial_size.0 + 1) as u32,
    );
    // buffer for pbs output
    let mut d_lwe_array_out_pbs_buffer =
        stream.malloc::<u64>(nos * level_count_cbs.0 as u32 * (polynomial_size.0 + 1) as u32);
    // vector for input of lwe ciphertexts
    let mut d_lwe_array_in = stream.malloc::<u64>(nos * (lwe_dimension.0 + 1) as u32);
    // vector for shifted lwe input
    let mut d_lwe_array_in_shifted_buffer =
        stream.malloc::<u64>(nos * level_count_cbs.0 as u32 * (lwe_dimension.0 + 1) as u32);
    // lut vector for pbs
    let mut d_lut_vector = stream.malloc::<u64>(
        level_count_cbs.0 as u32 * (glwe_dimension.0 as u32 + 1) * polynomial_size.0 as u32,
    );
    // indexes of lut vectors
    let mut d_lut_vector_indexes = stream.malloc::<u32>(nos * level_count_cbs.0 as u32);

    let mut d_fp_ksk_array = stream.malloc::<u64>(
        (polynomial_size.0 as u32 + 1)
            * (glwe_dimension.0 as u32 + 1)
            * (glwe_dimension.0 as u32 + 1)
            * level_pksk.0 as u32
            * polynomial_size.0 as u32,
    );

    let mut h_fp_ksk_array: Vec<u64> = vec![];

    let mut cnt = 0;
    let mut vec_cnt = 0;
    for iter in vec_pfksk.fpksk_iter_mut() {
        vec_cnt += 1;
        for iter2 in iter.bit_decomp_iter() {
            for iter3 in iter2.tensor.iter() {
                h_fp_ksk_array.push(*iter3 as u64);
                cnt += 1;
            }
        }
    }
    unsafe {
        // fill device lwe input with same ciphertext
        stream.copy_to_gpu::<u64>(&mut d_lwe_array_in, &mut lwe_in.tensor.as_slice());
        stream.copy_to_gpu::<u32>(&mut d_lut_vector_indexes, &mut h_lut_vector_indexes);
        stream.copy_to_gpu::<u64>(&mut d_fp_ksk_array, &mut h_fp_ksk_array);
    }

    unsafe {
        cuda_circuit_bootstrap_64(
            stream.stream_handle().0,
            0 as u32,
            d_ggsw_out.as_mut_c_ptr(),
            d_lwe_array_in.as_c_ptr(),
            d_bsk_fourier.as_c_ptr(),
            d_fp_ksk_array.as_mut_c_ptr(),
            d_lwe_array_in_shifted_buffer.as_mut_c_ptr(),
            d_lut_vector.as_mut_c_ptr(),
            d_lut_vector_indexes.as_c_ptr(),
            d_lwe_array_out_pbs_buffer.as_mut_c_ptr(),
            d_lwe_array_in_fp_ks_buffer.as_mut_c_ptr(),
            delta_log.0 as u32,
            polynomial_size.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            level_bsk.0 as u32,
            base_log_bsk.0 as u32,
            level_pksk.0 as u32,
            base_log_pksk.0 as u32,
            level_count_cbs.0 as u32,
            base_log_cbs.0 as u32,
            nos,
            stream.get_max_shared_memory().unwrap() as u32,
        );
    }
    let mut cuda_engine = CudaEngine::new(()).unwrap();
    let d_ciphertext: CudaGgswCiphertext64 = CudaGgswCiphertext64(CudaGgswCiphertext {
        d_vec: d_ggsw_out,
        glwe_dimension,
        polynomial_size,
        decomposition_level_count: level_count_cbs,
        decomposition_base_log: base_log_cbs,
    });
    let cbs_res_cuda: GgswCiphertext64 =
        cuda_engine.convert_ggsw_ciphertext(&d_ciphertext).unwrap();

    let glwe_size = glwe_dimension.to_glwe_size();

    //print the key to check if the RLWE in the GGSW seem to be well created
    println!("RLWE secret key:\n{:?}", glwe_sk);
    let mut decrypted = PlaintextList::allocate(
        0_u64,
        PlaintextCount(polynomial_size.0 * level_count_cbs.0 * glwe_size.0),
    );
    glwe_sk.decrypt_glwe_list(&mut decrypted, &cbs_res_cuda.0.as_glwe_list());

    let level_size = polynomial_size.0 * glwe_size.0;

    println!("\nGGSW decryption:");
    for (level_idx, level_decrypted_glwe) in decrypted
        .sublist_iter(PlaintextCount(level_size))
        .enumerate()
    {
        for (decrypted_glwe, original_polynomial_from_glwe_sk) in level_decrypted_glwe
            .sublist_iter(PlaintextCount(polynomial_size.0))
            .take(glwe_dimension.0)
            .zip(glwe_sk.as_polynomial_list().polynomial_iter())
        {
            let current_level = level_idx + 1;
            let mut expected_decryption = PlaintextList::allocate(
                0u64,
                PlaintextCount(original_polynomial_from_glwe_sk.polynomial_size().0),
            );
            expected_decryption
                .as_mut_tensor()
                .fill_with_copy(original_polynomial_from_glwe_sk.as_tensor());

            let multiplying_factor = 0u64.wrapping_sub(value);

            expected_decryption
                .as_mut_tensor()
                .update_with_wrapping_scalar_mul(&multiplying_factor);

            let decomposer =
                SignedDecomposer::new(base_log_cbs, DecompositionLevelCount(current_level));

            expected_decryption
                .as_mut_tensor()
                .update_with(|coeff| *coeff >>= 64 - base_log_cbs.0 * current_level);

            let mut decoded_glwe =
                PlaintextList::from_container(decrypted_glwe.as_tensor().as_container().to_vec());

            decoded_glwe.as_mut_tensor().update_with(|coeff| {
                *coeff = decomposer.closest_representable(*coeff)
                    >> (64 - base_log_cbs.0 * current_level)
            });

            assert_eq!(
                expected_decryption.as_tensor().as_slice(),
                decoded_glwe.as_tensor().as_slice()
            );
        }
        let last_decrypted_glwe = level_decrypted_glwe
            .sublist_iter(PlaintextCount(polynomial_size.0))
            .rev()
            .next()
            .unwrap();

        let mut last_decoded_glwe =
            PlaintextList::from_container(last_decrypted_glwe.as_tensor().as_container().to_vec());

        let decomposer = SignedDecomposer::new(base_log_cbs, level_count_cbs);

        last_decoded_glwe.as_mut_tensor().update_with(|coeff| {
            *coeff = decomposer.closest_representable(*coeff)
                >> (64 - base_log_cbs.0 * level_count_cbs.0)
        });

        let mut expected_decryption = PlaintextList::allocate(0u64, last_decoded_glwe.count());

        *expected_decryption.as_mut_tensor().first_mut() = value;

        assert_eq!(
            expected_decryption.as_tensor().as_slice(),
            last_decoded_glwe.as_tensor().as_slice()
        );
    }
}
