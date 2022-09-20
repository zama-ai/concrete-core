use crate::backends::cuda::private::device::{CudaStream, GpuIndex};
use crate::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::commons::crypto::secret::GlweSecretKey;
use crate::commons::math::polynomial::PolynomialList;
use crate::commons::math::tensor::{AsMutTensor, AsRefSlice, AsRefTensor};
use crate::prelude::*;
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::UnixSeeder;
use concrete_cuda::cuda_bind::cuda_cmux_tree_64;

#[test]
pub fn test_cuda_cmux_tree() {
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(1);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(6);
    let delta_log = 60;

    let std = LogStandardDev::from_log_standard_dev(-60.);

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
    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
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
    assert_eq!(lut_number as u64, witness % (1 << (64 - delta_log)))
}
