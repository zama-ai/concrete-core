use crate::backends::cuda::private::device::{CudaStream, GpuIndex};
use crate::backends::cuda::private::wopbs::{
    circuit_bootstrap_boolean_cuda_vertical_packing, cuda_vertical_packing,
};
use crate::backends::fft::private::crypto::bootstrap::{
    fill_with_forward_fourier_scratch, FourierLweBootstrapKey,
};
use crate::backends::fft::private::crypto::wop_pbs::{
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
use crate::prelude::*;
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::UnixSeeder;
use concrete_cuda::cuda_bind::{
    cuda_cmux_tree_64, cuda_convert_lwe_bootstrap_key_64, cuda_extract_bits_64,
    cuda_initialize_twiddles, cuda_synchronize_device,
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
        let mut h_luts = PolynomialList::allocate(0u64, PolynomialCount(num_lut), polynomial_size);
        for (i, mut polynomial) in h_luts.polynomial_iter_mut().enumerate() {
            polynomial
                .as_mut_tensor()
                .fill_with_element((i as u64 % (1 << (64 - delta_log))) << delta_log);

            let mut h_lut = polynomial.as_tensor().as_slice().to_vec();
            let mut h_zeroes = vec![0_u64; polynomial_size.0];
            // println!("lut {}) {}", i, h_lut[0]);

            // Mask is zero
            h_concatenated_luts.append(&mut h_zeroes);
            // Body is something else
            h_concatenated_luts.append(&mut h_lut);
        }

        // Now we have (2**r GLWE ciphertexts)
        assert_eq!(h_concatenated_luts.len(), num_lut * glwe_size);
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
        let witness = value;
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

        let mut d_result = stream.malloc::<u64>(glwe_size as u32);
        unsafe {
            cuda_cmux_tree_64(
                stream.stream_handle().0,
                gpu_index.0 as u32,
                d_result.as_mut_c_ptr(),
                d_concatenated_mtree.as_c_ptr(),
                d_concatenated_luts.as_c_ptr(),
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                r as u32,
                stream.get_max_shared_memory().unwrap() as u32,
            );
        }

        let mut h_result = vec![49u64; glwe_size];
        unsafe {
            stream.copy_to_cpu::<u64>(&mut h_result, &d_result);
        }
        assert_eq!(h_result.len(), glwe_size);

        let glwe_result = GlweCiphertext::from_container(h_result, polynomial_size);

        let mut decrypted_result =
            PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
        rlwe_sk.decrypt_glwe(&mut decrypted_result, &glwe_result);
        let lut_number =
            ((*decrypted_result.tensor.first() as f64) / (1u64 << delta_log) as f64).round();

        println!("\nresult: {:?}", decrypted_result.tensor.first());
        // println!("\nresult: {:?}", decrypted_result.tensor.as_container());
        println!("witness : {:?}", witness % (1 << (64 - delta_log)));
        println!("lut_number: {}", lut_number);
        // println!(
        //     "lut value  : {:?}",
        //     h_luts[witness as usize]
        // );
        println!("Done!");
        assert_eq!(lut_number as u64, witness % (1 << (64 - delta_log)));
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
