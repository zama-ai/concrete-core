use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::crypto::wop_pbs::{circuit_bootstrap_binary, extract_bits};
use crate::backends::fftw::private::math::fft::Complex64;
use crate::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::commons::math::decomposition::SignedDecomposer;
use crate::commons::math::tensor::{AsMutTensor, AsRefSlice, AsRefTensor};
use crate::commons::test_tools;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::parameters::{
    CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount,
    FunctionalPackingKeyswitchKeyCount, GlweDimension, LweDimension, LweSize, PlaintextCount,
    PolynomialSize,
};
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::{Seeder, UnixSeeder};

// Extract all the bits of a LWE
#[test]
pub fn test_extract_bits() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(585);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_ksk = DecompositionLevelCount(7);
    let base_log_ksk = DecompositionBaseLog(4);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let number_of_bits_of_message_including_padding = 5_usize;
    // Tests take about 2-3 seconds on a laptop with this number
    let number_of_test_runs = 32;

    const UNSAFE_SECRET: u128 = 0;
    let mut seeder = UnixSeeder::new(UNSAFE_SECRET);

    let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(seeder.seed(), &mut seeder);

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut coef_bsk = StandardBootstrapKey::allocate(
        0_u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_small_sk, &rlwe_sk, std, &mut encryption_generator);

    // allocation for the bootstrapping key
    let mut fourier_bsk: FourierBootstrapKey<_, u64> = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

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

    ////////////////////////////////////////////////////////////////////////////////////////////////

    for _ in 0..number_of_test_runs {
        // Generate a random plaintext in [0; 2^{number_of_bits_of_message_including_padding}[
        let val = test_tools::random_uint_between(
            0..2u64.pow(number_of_bits_of_message_including_padding as u32),
        );

        // Encryption
        let message = Plaintext(val << delta_log.0);
        println!("{:?}", message);
        let mut lwe_in = LweCiphertext::allocate(0u64, LweSize(polynomial_size.0 + 1));
        lwe_big_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

        // Bit extraction
        // Extract all the bits
        let number_values_to_extract = ExtractedBitsCount(64 - delta_log.0);

        let mut lwe_out_list = LweList::allocate(
            0u64,
            ksk_lwe_big_to_small.lwe_size(),
            CiphertextCount(number_values_to_extract.0),
        );

        extract_bits(
            delta_log,
            &mut lwe_out_list,
            &lwe_in,
            &ksk_lwe_big_to_small,
            &fourier_bsk,
            &mut buffers,
            number_values_to_extract,
        );

        // Decryption of extracted bit
        for (i, result_ct) in lwe_out_list.ciphertext_iter().rev().enumerate() {
            let mut decrypted_message = Plaintext(0_u64);
            lwe_small_sk.decrypt_lwe(&mut decrypted_message, &result_ct);
            // Round after decryption using decomposer
            let decrypted_rounded = decomposer.closest_representable(decrypted_message.0);
            // Bring back the extracted bit found in the MSB in the LSB
            let decrypted_extract_bit = decrypted_rounded >> 63;
            println!("extracted bit : {:?}", decrypted_extract_bit);
            println!("{:?}", decrypted_message);
            assert_eq!(
                ((message.0 >> delta_log.0) >> i) & 1,
                decrypted_extract_bit,
                "Bit #{}, for plaintext {:#066b}",
                delta_log.0 + i,
                message.0
            )
        }
    }
}

// Test the circuit bootstrapping with private functional ks
// Verify the decryption has the expected content
#[test]
pub fn test_circuit_bootstrapping_binary() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(2);
    let lwe_dimension = LweDimension(10);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(15);

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

    // Allocation of the fourier bootstrapping key
    let mut fourier_bsk: FourierBootstrapKey<_, u64> = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&std_bsk, &mut buffers);

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

    vec_pfksk.fill_with_fpksk_for_circuit_bootstrap(
        &lwe_sk_bs_output,
        &glwe_sk,
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

    // Execute the CBS
    circuit_bootstrap_binary(
        &fourier_bsk,
        &lwe_in,
        &mut cbs_res,
        &mut buffers,
        delta_log,
        &vec_pfksk,
    );

    let glwe_size = glwe_dimension.to_glwe_size();

    //print the key to check if the RLWE in the GGSW seem to be well created
    println!("RLWE secret key:\n{:?}", glwe_sk);
    let mut decrypted = PlaintextList::allocate(
        0_u64,
        PlaintextCount(polynomial_size.0 * level_count_cbs.0 * glwe_size.0),
    );
    glwe_sk.decrypt_glwe_list(&mut decrypted, &cbs_res.as_glwe_list());

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
                .update_with_scalar_mul(&multiplying_factor);

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
