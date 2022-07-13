use crate::backends::fftw::private::crypto::bootstrap::{FourierBootstrapKey, FourierBuffers};
use crate::backends::fftw::private::crypto::wop_pbs::extract_bits;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::commons::crypto::bootstrap::StandardBootstrapKey;
use crate::commons::crypto::encoding::Plaintext;
use crate::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::commons::math::decomposition::SignedDecomposer;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::commons::test_tools;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, GlweDimension,
    LweDimension, LweSize, PolynomialSize,
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
        let result_lwe = extract_bits(
            delta_log,
            &lwe_in,
            &ksk_lwe_big_to_small,
            &fourier_bsk,
            &mut buffers,
            number_values_to_extract,
        );

        // Decryption of extracted bit
        for (i, result_ct) in result_lwe.ciphertext_iter().rev().enumerate() {
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
