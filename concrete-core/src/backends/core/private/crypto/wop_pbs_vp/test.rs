use crate::backends::core::private::crypto::encoding::{Plaintext, PlaintextList};
use crate::backends::core::private::crypto::glwe::{
    FunctionalPackingKeyswitchKey, GlweCiphertext, PackingKeyswitchKey,
};
use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::backends::core::private::math::polynomial::Polynomial;
use concrete_commons::dispersion::{LogStandardDev, StandardDev, Variance};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    PolynomialSize,
};
use std::time::Instant;

use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
};
use crate::backends::core::private::crypto::circuit_bootstrap::DeltaLog;
use crate::backends::core::private::crypto::ggsw::{FourierGgswCiphertext, StandardGgswCiphertext};
use crate::backends::core::private::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use crate::backends::core::private::crypto::vertical_packing::{
    vertical_packing_cbs_binary, vertical_packing_cbs_binary_v0, vertical_packing_cbs_binary_v1,
};
use crate::backends::core::private::crypto::wop_pbs_vp::{extract_bit, extract_bit_v0_v1};
use crate::backends::core::private::math::fft::Complex64;
use crate::backends::core::private::math::tensor::as_slice::AsRefSlice;
use crate::backends::core::private::math::tensor::{AsMutTensor, AsRefTensor};
use crate::backends::core::private::math::torus::UnsignedTorus;
use concrete_commons::dispersion::DispersionParameter;
use concrete_commons::key_kinds::BinaryKeyKind;

// Extract all the bits of a LWE
#[test]
pub fn test_extract_bit() {
    //Define setting
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(585);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_ksk = DecompositionLevelCount(7);
    let base_log_ksk = DecompositionBaseLog(4);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
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
        0 as u64,
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

    let delta_log = DeltaLog(59);
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////

    // Encryption
    let message = Plaintext(0b10111 << delta_log.0);
    println!("{:?}", message);
    let mut lwe_in = LweCiphertext::allocate(0u64, LweSize(polynomial_size.0 + 1));
    lwe_big_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    // Bit extraction
    let number_values_to_extract = 5_usize;
    let (result_lwe, result_delta) = extract_bit(
        delta_log,
        &mut lwe_in,
        &ksk_lwe_big_to_small,
        &mut fourier_bsk,
        &mut buffers,
        number_values_to_extract,
    );
    println!("{:?}", &result_delta);

    // Decryption of extracted bit
    for i in 0..result_lwe.len() {
        let mut decrypted_message = Plaintext(0 as u64);
        let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result_lwe[i]);
        let decrypted_extract_bit =
            (((decrypted_message.0 as f64) / (1u64 << (result_delta[i].0)) as f64).round()) as u64
                % (1 << (64 - result_delta[i].0 as u64));
        println!("extracted bit : {:?}", decrypted_extract_bit);
        println!("{:?}", decrypted_message);
        assert_eq!(((message.0 >> delta_log.0) >> i) & 1, decrypted_extract_bit)
    }
}

// test v -1
// Extract bit give LWE( Delta . alpha )
// CBS use pfksk
#[test]
pub fn circuit_bs_vertical_packing_with_extract_bit_v_minus_one() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);
    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);
    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);
    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);
    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);

    let std_small =
        StandardDev::from_standard_dev(0.00000000000000000022148688116005568513645324585951557896);
    let std_big = StandardDev::from_standard_dev(0.00000032274924032514939445601463118067605957);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let lwe_big_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );

    coef_bsk.fill_with_new_key(
        &lwe_small_sk,
        &rlwe_sk,
        std_small,
        &mut encryption_generator,
    );
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

    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0 as u64,
        level_ksk,
        base_log_ksk,
        lwe_big_sk.key_size(),
        lwe_small_sk.key_size(),
    );
    ksk_lwe_big_to_small.fill_with_keyswitch_key(
        &lwe_big_sk,
        &lwe_small_sk,
        std_big,
        &mut encryption_generator,
    );

    // creation of all the pfksk for the circuit bootstrapping
    let vec_fpksk = create_vec_pfksk(
        level_pksk,
        base_log_pksk,
        &rlwe_sk,
        &rlwe_sk,
        &lwe_big_sk,
        std_small,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(61);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'

    let mut witness = 0;
    for _ in 0..10 {
        let mut vec_result_lwe = vec![];
        let mut vec_result_delta = vec![];

        // create loop * LWE and extract each bit of all LWE
        for _ in 0..1 {
            let message = Plaintext(0b10 << delta_log.0);
            let mut lwe_in = LweCiphertext::allocate(0u64, LweSize(polynomial_size.0 + 1));
            lwe_big_sk.encrypt_lwe(&mut lwe_in, &message, std_big, &mut encryption_generator);
            let number_values_to_extract = 2_usize;

            let (mut result_lwe, mut result_delta) = extract_bit(
                delta_log,
                &mut lwe_in,
                &ksk_lwe_big_to_small,
                &mut fourier_bsk,
                &mut buffers,
                number_values_to_extract,
            );
            vec_result_lwe.append(&mut result_lwe);
            vec_result_delta.append(&mut result_delta);
        }

        // creation of a LUT
        let delta_lut = DeltaLog(59);
        let mut lut = vec![];
        let mut lut_size = polynomial_size.0;
        if lut_size < (1 << vec_result_lwe.len()) {
            lut_size = 1 << vec_result_lwe.len();
        }
        let mut tmp = 0;
        for i in 0..lut_size {
            lut.push(((i as u64 + tmp) % (1 << (64 - delta_lut.0))) << delta_lut.0);
            if i % (1 << (64 - delta_lut.0)) == 0 {
                tmp += 1;
            }
        }

        // KS all the extracted bit
        let mut vec_lwe_ks = vec![];
        for lwe in vec_result_lwe.iter() {
            let mut lwe_out_ks = LweCiphertext::allocate(0_u64, LweSize(lwe_dimension.0 + 1));
            ksk_lwe_big_to_small.keyswitch_ciphertext(&mut lwe_out_ks, &lwe);
            vec_lwe_ks.push(lwe_out_ks.clone());
        }

        // Perform CBS + VP
        let vec_lut = vec![lut; 2];
        let mut vec_lwe_in = vec_lwe_ks.clone();
        vec_result_delta.reverse();
        vec_lwe_in.reverse();
        let result = vertical_packing_cbs_binary(
            vec_lut,
            &mut buffers,
            &mut fourier_bsk,
            &vec_lwe_in.clone(),
            level_cbs,
            base_log_cbs,
            vec_result_delta.clone(),
            &vec_fpksk,
        );

        // decrypt result
        let mut decrypted_message = Plaintext(0 as u64);
        let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result[1]);
        let num_lut =
            (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;

        // print information if the result is wrong
        if num_lut % 32 != 3 {
            witness += 1;
            //println!("-----------------------");
            for i in 0..vec_lwe_in.len() {
                let mut decrypted_message = Plaintext(0 as u64);
                //let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
                lwe_small_sk.decrypt_lwe(&mut decrypted_message, &vec_lwe_in[i]);
                let result = (((decrypted_message.0 as f64)
                    / (1u64 << (vec_result_delta[i].0)) as f64)
                    .round()) as u64;
                println!("extract bit result : {:?}", result);
                println!("Delta              : {:?}", vec_result_delta[i].0);
                println!("{:?}", decrypted_message);
            }
            println!("value lut result : {:?}", num_lut);
            println!("{:?}", decrypted_message);
            println!("-----------------------");
        }
    }
    assert_eq!(witness, 0)
}

//test v0
// Extract bit give LWE( alpha . modulus/2 )
// CBS use pfksk
#[test]
pub fn circuit_bs_vertical_packing_with_extract_bit_v0() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);

    let std_small =
        StandardDev::from_standard_dev(0.00000000000000022148688116005568513645324585951);
    let std_big = StandardDev::from_standard_dev(0.000061200133780220371345);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let lwe_big_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(
        &lwe_small_sk,
        &rlwe_sk,
        Variance(std_small.get_variance()),
        &mut encryption_generator,
    );
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

    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0 as u64,
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

    // creation of all the pfksk for the circuit bootstrapping
    let vec_fpksk = create_vec_pfksk(
        level_pksk,
        base_log_pksk,
        &rlwe_sk,
        &rlwe_sk,
        &lwe_big_sk,
        std_small,
        &mut encryption_generator,
    );
    let delta_log = DeltaLog(64 - 10);
    let delta_lut = DeltaLog(64 - 10);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'

    let mut witness = 0;

    for _ in 0..10 {
        let mut vec_result_lwe = vec![];

        // encrypt Loop * messages and extract bits
        for _ in 0..1 {
            let message = Plaintext(0b1111110101 << delta_log.0);
            let mut lwe_in =
                LweCiphertext::allocate(0u64, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
            lwe_big_sk.encrypt_lwe(
                &mut lwe_in,
                &message,
                Variance(std_big.get_variance()),
                &mut encryption_generator,
            );
            let number_values_to_extract = 10_usize;

            let mut result_lwe = extract_bit_v0_v1(
                delta_log,
                &mut lwe_in,
                &ksk_lwe_big_to_small,
                &mut fourier_bsk,
                &mut buffers,
                number_values_to_extract,
            );
            vec_result_lwe.append(&mut result_lwe);
        }

        // decrypt all extracted bit
        for i in 0..vec_result_lwe.len() {
            let mut decrypted_message = Plaintext(0 as u64);
            lwe_small_sk.decrypt_lwe(&mut decrypted_message, &vec_result_lwe[i]);
            let extract_bit_result =
                (((decrypted_message.0 as f64) / (1u64 << (63)) as f64).round()) as u64;
            println!("{:?}", extract_bit_result);
            println!("{:?}", decrypted_message);
        }

        // LUt creation
        let mut lut = vec![];
        let mut lut_size = polynomial_size.0;
        if lut_size < (1 << vec_result_lwe.len()) {
            lut_size = 1 << vec_result_lwe.len();
        }
        let mut tmp = 0;
        for i in 0..lut_size {
            lut.push(((i as u64 + tmp) % (1 << (64 - delta_lut.0))) << delta_lut.0);
            if (i + 1) % (1 << (64 - delta_lut.0)) == 0 {
                tmp += 1;
            }
        }
        let vec_lut = vec![lut.clone(); 1];

        // perform CBS + VP
        let mut vec_lwe_in = vec_result_lwe;
        vec_lwe_in.reverse();
        let result = vertical_packing_cbs_binary_v0(
            vec_lut,
            &mut buffers,
            &mut fourier_bsk,
            &vec_lwe_in,
            level_cbs,
            base_log_cbs,
            &vec_fpksk,
        );

        // decrypt result
        let mut decrypted_message = Plaintext(0 as u64);
        let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result[0]);
        let num_lut =
            (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;

        // print information if the result is wrong
        if num_lut != 1013 {
            println!("{:?}", decrypted_message);
            println!("{:?}", num_lut);
            witness += 1;
        }
        println!("{:?}", num_lut);
    }
    assert_eq!(witness, 0);
}

//test v1
// Extract bit give LWE( alpha . modulus/2 )
// CBS use ksk + external product
// NOT WORK NEED PARAMETERS ?
#[test]
pub fn circuit_bs_vertical_packing_with_extract_bit_v1() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(481);

    let level_bsk = DecompositionLevelCount(9);
    let base_log_bsk = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(9);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(6);

    let level_ext = DecompositionLevelCount(4);
    let base_log_ext = DecompositionBaseLog(6);

    let std = LogStandardDev::from_log_standard_dev(-100.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_small_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
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

    let lwe_sk_bs_output = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    let lwe_big_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());

    let mut ksk_lwe_big_to_small = LweKeyswitchKey::allocate(
        0 as u64,
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

    // creation of all the pksk for the circuit bootstrapping
    let mut pksk = PackingKeyswitchKey::allocate(
        0 as u64,
        level_pksk,
        base_log_pksk,
        LweDimension(polynomial_size.0 * rlwe_dimension.0),
        rlwe_dimension,
        polynomial_size,
    );

    pksk.fill_with_packing_keyswitch_key(
        &lwe_sk_bs_output,
        &rlwe_sk,
        std,
        &mut encryption_generator,
    );

    let vec_ggsw = create_ggsw(
        level_ext,
        base_log_ext,
        &rlwe_sk,
        std,
        &mut encryption_generator,
    );

    let mut vec_fourier_ggsw = vec![];
    for mut ggsw in vec_ggsw.iter() {
        let mut fourier_ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            rlwe_sk.polynomial_size(),
            rlwe_sk.key_size().to_glwe_size(),
            level_ext,
            base_log_ext,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(
            &mut fourier_ggsw,
            &mut ggsw,
            &mut buffers,
        );
        vec_fourier_ggsw.push(fourier_ggsw);
    }

    let delta_log = DeltaLog(61);
    let delta_lut = DeltaLog(59);
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for _ in 0..10 {
        let mut vec_result_lwe = vec![];
        // create loop * LWE and extract each bit of all LWE
        for _ in 0..6 {
            let message = Plaintext(0b10 << delta_log.0);
            let mut lwe_in = LweCiphertext::allocate(0u64, LweSize(polynomial_size.0 + 1));
            lwe_big_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);
            let number_values_to_extract = 2_usize;

            let mut result_lwe = extract_bit_v0_v1(
                delta_log,
                &mut lwe_in,
                &ksk_lwe_big_to_small,
                &mut fourier_bsk,
                &mut buffers,
                number_values_to_extract,
            );
            vec_result_lwe.append(&mut result_lwe);
        }

        for i in 0..vec_result_lwe.len() {
            let mut decrypted_message = Plaintext(0 as u64);
            lwe_small_sk.decrypt_lwe(&mut decrypted_message, &vec_result_lwe[i]);
            let num_lut = (((decrypted_message.0 as f64) / (1u64 << (63)) as f64).round()) as u64;
            println!("{:?}", num_lut);
            println!("{:?}", decrypted_message);
        }

        // LUT creation
        let mut lut = vec![];
        let mut lut_size = polynomial_size.0;
        if lut_size < (1 << vec_result_lwe.len()) {
            lut_size = 1 << vec_result_lwe.len();
        }
        let mut tmp = 0;
        for i in 0..lut_size {
            lut.push(((i as u64 + tmp) % (1 << (64 - delta_lut.0))) << delta_lut.0);
            if (i + 1) % (1 << 10) == 0 {
                tmp += 1;
            }
        }

        let vec_lut = vec![lut; 2];
        let mut vec_lwe_in = vec_result_lwe;
        vec_lwe_in.reverse();
        let result = vertical_packing_cbs_binary_v1(
            vec_lut,
            &mut buffers,
            &mut fourier_bsk,
            &vec_lwe_in,
            level_cbs,
            base_log_cbs,
            &vec_fourier_ggsw,
            &pksk,
        );

        println!("\n");
        let mut decrypted_message = Plaintext(0 as u64);
        let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result[0]);
        let lut_1 =
            (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
        println!("{:?}", lut_1);

        let mut decrypted_message = Plaintext(0 as u64);
        let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk.decrypt_lwe(&mut decrypted_message, &result[1]);
        let lut_2 =
            (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
        println!("{:?}", lut_2);
        assert_eq!(lut_1, lut_2)
    }
}

/////////////////////////////////////////////////////////////
////////////////// for param creation ///////////////////////
/////////////////////////////////////////////////////////////

pub fn create_vec_pfksk<LWEKeyCont, GLWEKeyCont, Scalar>(
    level_pksk: DecompositionLevelCount,
    base_log_pksk: DecompositionBaseLog,
    encrypted_glwe_key: &GlweSecretKey<BinaryKeyKind, GLWEKeyCont>,
    glwe_key: &GlweSecretKey<BinaryKeyKind, GLWEKeyCont>,
    lwe_key: &LweSecretKey<BinaryKeyKind, LWEKeyCont>,
    std: impl DispersionParameter,
    mut encryption_generator: &mut EncryptionRandomGenerator,
) -> Vec<FunctionalPackingKeyswitchKey<Vec<Scalar>>>
where
    LweSecretKey<BinaryKeyKind, LWEKeyCont>: AsRefTensor<Element = Scalar>,
    GlweSecretKey<BinaryKeyKind, GLWEKeyCont>: AsRefTensor<Element = Scalar>,
    Scalar: UnsignedTorus,
{
    let glwe_dimension = encrypted_glwe_key
        .key_size()
        .to_glwe_size()
        .to_glwe_dimension();
    let mut vec_fpksk = vec![
        FunctionalPackingKeyswitchKey::allocate(
            Scalar::ZERO,
            level_pksk,
            base_log_pksk,
            lwe_key.key_size(),
            glwe_dimension,
            encrypted_glwe_key.polynomial_size()
        );
        glwe_dimension.0 + 1
    ];
    for i in 0..glwe_dimension.0 {
        vec_fpksk[i].fill_with_functional_packing_keyswitch_key(
            lwe_key,
            glwe_key,
            std.clone(),
            &mut encryption_generator,
            |x| Scalar::ZERO.wrapping_sub(x),
            &Polynomial::from_container(
                encrypted_glwe_key
                    .as_polynomial_list()
                    .get_polynomial(i)
                    .tensor
                    .into_container()
                    .to_vec(),
            ),
        );
    }

    let mut v = vec![Scalar::ZERO; glwe_key.polynomial_size().0];
    v[0] = Scalar::ONE;
    vec_fpksk[glwe_dimension.0].fill_with_functional_packing_keyswitch_key(
        lwe_key,
        glwe_key,
        std,
        &mut encryption_generator,
        |x| x,
        &Polynomial::from_container(v),
    );
    vec_fpksk
}

pub fn create_ggsw<GLWEKeyCont, Scalar>(
    level_ext: DecompositionLevelCount,
    base_log_ext: DecompositionBaseLog,
    glwe_key: &GlweSecretKey<BinaryKeyKind, GLWEKeyCont>,
    std: LogStandardDev,
    mut encryption_generator: &mut EncryptionRandomGenerator,
) -> Vec<StandardGgswCiphertext<Vec<Scalar>>>
where
    GlweSecretKey<BinaryKeyKind, GLWEKeyCont>: AsRefTensor<Element = Scalar>,
    Scalar: UnsignedTorus,
{
    let glwe_dimension = glwe_key.key_size().to_glwe_size().to_glwe_dimension();
    let mut glwe_out = GlweCiphertext::allocate(
        Scalar::ZERO,
        glwe_key.polynomial_size(),
        glwe_key.key_size().to_glwe_size(),
    );
    let mut vec_ggsw = vec![];
    for i in 0..glwe_dimension.0 {
        let mut vec_tensor = vec![];
        for j in 1..=level_ext.0 {
            for k in 0..glwe_dimension.0 {
                glwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
                let mut vec = vec![Scalar::ZERO; glwe_out.polynomial_size().0];
                let mut polynomial_out =
                    Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
                let mut polynomial_out2 =
                    Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
                vec[0] = Scalar::ONE << (64 - base_log_ext.0 * j);

                // polynomial with S_i * 1<<(modulus - beta * level )
                polynomial_out.update_with_wrapping_add_mul(
                    &glwe_key.as_polynomial_list().get_polynomial(i),
                    &Polynomial::from_container(vec),
                );

                // polynomial with S_k * S_i * 1<<(modulus - beta * level )
                polynomial_out2.update_with_wrapping_add_mul(
                    &glwe_key.as_polynomial_list().get_polynomial(k),
                    &polynomial_out,
                );
                let encoded = PlaintextList::from_container(polynomial_out2.tensor);

                //encrypt polynomial S_k * S_i * 1<<(modulus - beta * level )
                glwe_key.encrypt_glwe(&mut glwe_out, &encoded, std, &mut encryption_generator);
                let tmp_tensor = glwe_out.tensor.as_container();
                vec_tensor.append(&mut tmp_tensor.to_vec());
            }

            glwe_out.as_mut_tensor().fill_with(|| Scalar::ZERO);
            let mut vec = vec![Scalar::ZERO; glwe_out.polynomial_size().0];
            let mut polynomial_out =
                Polynomial::from_container(vec![Scalar::ZERO; glwe_out.polynomial_size().0]);
            vec[0] = Scalar::ONE << (64 - base_log_ext.0 * j);
            // polynomial with  -S_i * 1<<(modulus - beta * level )
            polynomial_out.update_with_wrapping_sub_mul(
                &glwe_key.as_polynomial_list().get_polynomial(i),
                &Polynomial::from_container(vec),
            );
            let encoded = PlaintextList::from_container(polynomial_out.tensor);

            //encrypt polynomial - S_i * 1<<(modulus - beta * level )
            glwe_key.encrypt_glwe(&mut glwe_out, &encoded, std, &mut encryption_generator);
            let tmp_tensor = glwe_out.tensor.as_container();
            vec_tensor.append(&mut tmp_tensor.to_vec());
        }
        let ggsw = StandardGgswCiphertext::from_container(
            vec_tensor.clone(),
            glwe_key.key_size().to_glwe_size(),
            glwe_key.polynomial_size(),
            base_log_ext,
        );

        vec_ggsw.push(ggsw);
    }
    vec_ggsw
}
