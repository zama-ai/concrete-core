use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
};

use crate::backends::core::private::crypto::circuit_bootstrap::{
    circuit_bootstrap, circuit_bootstrap_binary, circuit_bootstrap_v1, homomorphic_shift,
    homomorphic_shift_binary, DeltaLog,
};
use crate::backends::core::private::crypto::encoding::{Plaintext, PlaintextList};
use crate::backends::core::private::crypto::ggsw::{FourierGgswCiphertext, StandardGgswCiphertext};
//use crate::backends::core::private::crypto::glwe::functional_keyswitch
//::FunctionalPackingKeyswitchKey;
use crate::backends::core::private::crypto::glwe::{
    FunctionalPackingKeyswitchKey, GlweCiphertext, PackingKeyswitchKey,
};
use crate::backends::core::private::crypto::lwe::LweCiphertext;
use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::backends::core::private::crypto::vertical_packing::vertical_packing;
use crate::backends::core::private::math::fft::Complex64;
use crate::backends::core::private::math::polynomial::Polynomial;
use crate::backends::core::private::math::tensor::AsMutTensor;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    PlaintextCount, PolynomialSize,
};

use crate::backends::core::private::math::tensor::{AsRefSlice, AsRefTensor};
use crate::backends::core::private::math::torus::UnsignedTorus;

#[test]
pub fn test_homomorphic_shift() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(130);

    let level_bsk = DecompositionLevelCount(1);
    let base_log_bsk = DecompositionBaseLog(23);
    let level_cbs = DecompositionLevelCount(3);
    let base_log_cbs = DecompositionBaseLog(4);
    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    let delta_log = DeltaLog(59);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for i in 1..(1 << (64 - delta_log.0 - 1)) {
        let message = Plaintext((i as u64) << delta_log.0);

        let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
        let mut lwe_out =
            LweCiphertext::allocate(0u64, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
        lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

        // homomorphic_shift, return message << base_cbs * level_cbs
        homomorphic_shift(
            &fourier_bsk,
            |x| x,
            &mut lwe_out,
            &lwe_in,
            &mut buffers,
            level_cbs,
            base_log_cbs,
            delta_log,
        );
        let mut decrypted_message = Plaintext(0 as u64);
        lwe_sk.decrypt_lwe(&mut decrypted_message, &lwe_in);

        let mut decrypted_bs_message = Plaintext(0 as u64);
        let lwe_sk2 = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk2.decrypt_lwe(&mut decrypted_bs_message, &lwe_out);

        if ((decrypted_bs_message.0 as f64) / (1u64 << (64 - base_log_cbs.0 * level_cbs.0)) as f64)
            .round() as i64
            != ((decrypted_message.0 as f64) / (1u64 << delta_log.0) as f64).round() as i64
        {
            println!(
                "\ndecrypted message + shift :{:?}",
                ((decrypted_message.0 as f64) / (1u64 << delta_log.0) as f64).round()
            );
            println!("decrypted message: {:?}", decrypted_message);
            println!(
                "decrypted bs message + shift :{:?}",
                ((decrypted_bs_message.0 as f64)
                    / (1_u64 << (64 - base_log_cbs.0 * level_cbs.0)) as f64)
                    .round()
            );
            println!("decrypted bs message: {:?}", decrypted_bs_message);
        }
        assert_eq!(
            ((decrypted_bs_message.0 as f64) / (1u64 << (64 - base_log_cbs.0 * level_cbs.0)) as f64)
                .round() as i64,
            ((decrypted_message.0 as f64) / (1u64 << delta_log.0) as f64).round() as i64
        )
    }
}

#[test]
pub fn test_homomorphic_shift_binary() {
    // define settings
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(130);

    let level_bsk = DecompositionLevelCount(1);
    let base_log_bsk = DecompositionBaseLog(23);
    let level_cbs = DecompositionLevelCount(2);
    let base_log_cbs = DecompositionBaseLog(3);
    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level_bsk,
        base_log_bsk,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    let delta_log = DeltaLog(59);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////

    for i in 1..(1 << (64 - delta_log.0 - 1)) {
        let message = Plaintext((i as u64) << delta_log.0);

        let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
        let mut lwe_out =
            LweCiphertext::allocate(0u64, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
        lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

        // homomorphic_shift, return message << base_cbs * level_cbs
        homomorphic_shift_binary(
            &fourier_bsk,
            &mut lwe_out,
            &lwe_in,
            &mut buffers,
            level_cbs,
            base_log_cbs,
            delta_log,
        );
        let mut decrypted_message = Plaintext(0 as u64);
        lwe_sk.decrypt_lwe(&mut decrypted_message, &lwe_in);

        let mut decrypted_bs_message = Plaintext(0 as u64);
        let lwe_sk2 = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        lwe_sk2.decrypt_lwe(&mut decrypted_bs_message, &lwe_out);

        println!(
            "\ndecrypted message + shift :{:?}",
            ((decrypted_message.0 as f64) / (1u64 << delta_log.0) as f64).round()
        );
        println!("decrypted message: {:?}", decrypted_message);
        println!(
            "decrypted bs message + shift :{:?}",
            ((decrypted_bs_message.0 as f64)
                / (1_u64 << (64 - base_log_cbs.0 * level_cbs.0)) as f64)
                .round()
        );
        println!("decrypted bs message: {:?}", decrypted_bs_message);

        assert_eq!(
            (((decrypted_bs_message.0 as f64)
                / (1u64 << (64 - base_log_cbs.0 * level_cbs.0)) as f64)
                .round() as i64)
                % 2,
            (((decrypted_message.0 as f64) / (1u64 << delta_log.0) as f64).round() as i64) % 2
        )
    }
}

// test the CBS with private functional ks
// check if it's work with computing an external product
#[test]
pub fn test_cbs() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);

    let level_bsk = DecompositionLevelCount(3);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(7);
    let base_log_pksk = DecompositionBaseLog(4);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
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
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    // creation of all the pfksk for the circuit bootstrapping
    let vec_pfksk = create_vec_pfksk(
        level_pksk,
        base_log_pksk,
        &rlwe_sk,
        &rlwe_sk,
        &lwe_sk_bs_output,
        std,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(60);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'
    let value: u64 = 5;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    let mut res = circuit_bootstrap(
        &fourier_bsk,
        &lwe_in,
        &mut buffers,
        level_cbs,
        base_log_cbs,
        delta_log,
        |x| x,
        &vec_pfksk,
    );

    //print the key to check if the RLWE in the GGSW seem to be well created
    println!("RLWE secret key : \n{:?}", rlwe_sk);
    let mut decrypted =
        PlaintextList::from_container(vec![
            0_u64;
            polynomial_size.0 * level_cbs.0 * (rlwe_dimension.0 + 1)
        ]);
    rlwe_sk.decrypt_glwe_list(&mut decrypted, &res.as_glwe_list());
    println!("\nGGSW decryption : ");
    for i in decrypted.sublist_iter(PlaintextCount(polynomial_size.0)) {
        println!("{:?}", i);
    }
    println!();

    let mut ggsw = FourierGgswCiphertext::allocate(
        Complex64::new(0., 0.),
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
        level_cbs,
        base_log_cbs,
    );
    FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &mut res, &mut buffers);

    // encryption of a RLWE with the value [? ,0 ,0 ...,0]
    let mut vec = vec![0_u64; rlwe_sk.polynomial_size().0];
    vec[0] = 3_u64 << delta_log.0;
    let list = PlaintextList::from_container(vec);
    let mut rlwe_in = GlweCiphertext::allocate(
        0u64,
        rlwe_sk.polynomial_size(),
        rlwe_dimension.to_glwe_size(),
    );
    rlwe_sk.encrypt_glwe(&mut rlwe_in, &list, std, &mut encryption_generator);

    // RLWE out for the external product
    let mut rlwe_out = GlweCiphertext::allocate(
        0_u64,
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
    );

    ggsw.external_product(&mut rlwe_out, &rlwe_in, &mut buffers);

    // decrypted value of RLWEin
    let mut decrypted_input_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_input_ext_prod, &rlwe_in);
    let first_value_decrypted_input_ext_prod = decrypted_input_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    // decrypted value of RLWEout ( after external prod)
    let mut decrypted_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_ext_prod, &rlwe_out);
    let first_value_decrypted_ext_prod = decrypted_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    assert_eq!(
        ((first_value_decrypted_ext_prod as f64) / (1u64 << delta_log.0) as f64).round(),
        ((first_value_decrypted_input_ext_prod as f64) / (1u64 << delta_log.0) as f64).round()
            * value as f64
    );
}

// test the CBS with private functional ks
// check if it's work with computing an external product
#[test]
pub fn test_cbs_binary() {
    // define settings
    let polynomial_size = PolynomialSize(2048);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(585);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(15);

    let level_pksk = DecompositionLevelCount(2); //10?
    let base_log_pksk = DecompositionBaseLog(15); //2?

    let level_cbs = DecompositionLevelCount(1);
    let base_log_cbs = DecompositionBaseLog(10);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
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
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    // creation of all the pfksk for the circuit bootstrapping
    let vec_pfksk = create_vec_pfksk(
        level_pksk,
        base_log_pksk,
        &rlwe_sk,
        &rlwe_sk,
        &lwe_sk_bs_output,
        std,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(60);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'
    let value: u64 = 1;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    let mut res = circuit_bootstrap_binary(
        &fourier_bsk,
        &lwe_in,
        &mut buffers,
        level_cbs,
        base_log_cbs,
        delta_log,
        &vec_pfksk,
    );

    //print the key to check if the RLWE in the GGSW seem to be well created
    println!("RLWE secret key : \n{:?}", rlwe_sk);
    let mut decrypted =
        PlaintextList::from_container(vec![
            0_u64;
            polynomial_size.0 * level_cbs.0 * (rlwe_dimension.0 + 1)
        ]);
    rlwe_sk.decrypt_glwe_list(&mut decrypted, &res.as_glwe_list());
    println!("\nGGSW decryption : ");
    for i in decrypted.sublist_iter(PlaintextCount(polynomial_size.0)) {
        println!("{:?}", i);
    }
    println!();

    let mut ggsw = FourierGgswCiphertext::allocate(
        Complex64::new(0., 0.),
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
        level_cbs,
        base_log_cbs,
    );
    FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &mut res, &mut buffers);

    // encryption of a RLWE with the value [? ,0 ,0 ...,0]
    let mut vec = vec![0_u64; rlwe_sk.polynomial_size().0];
    vec[0] = 3_u64 << delta_log.0;
    let list = PlaintextList::from_container(vec);
    let mut rlwe_in = GlweCiphertext::allocate(
        0u64,
        rlwe_sk.polynomial_size(),
        rlwe_dimension.to_glwe_size(),
    );
    rlwe_sk.encrypt_glwe(&mut rlwe_in, &list, std, &mut encryption_generator);

    // RLWE out for the external product
    let mut rlwe_out = GlweCiphertext::allocate(
        0_u64,
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
    );

    ggsw.external_product(&mut rlwe_out, &rlwe_in, &mut buffers);

    // decrypted value of RLWEin
    let mut decrypted_input_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_input_ext_prod, &rlwe_in);
    let first_value_decrypted_input_ext_prod = decrypted_input_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    // decrypted value of RLWEout ( after external prod)
    let mut decrypted_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_ext_prod, &rlwe_out);
    let first_value_decrypted_ext_prod = decrypted_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    assert_eq!(
        ((first_value_decrypted_ext_prod as f64) / (1u64 << delta_log.0) as f64).round(),
        ((first_value_decrypted_input_ext_prod as f64) / (1u64 << delta_log.0) as f64).round()
            * value as f64
    );
}

#[test]
pub fn testpfksk() {
    // define settings
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(2);
    let lwe_dimension = LweDimension(10);

    let level_pksk = DecompositionLevelCount(1);
    let base_log_pksk = DecompositionBaseLog(24);

    let std = LogStandardDev::from_log_standard_dev(-55.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
        LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let delta_log = DeltaLog(55);

    let mut pksk = FunctionalPackingKeyswitchKey::allocate(
        0 as u64,
        level_pksk,
        base_log_pksk,
        lwe_dimension,
        rlwe_dimension,
        polynomial_size,
    );

    let mul: u64 = 7;
    let mut vec = vec![0u64; rlwe_sk.polynomial_size().0];
    vec[0] = 1;
    pksk.fill_with_functional_packing_keyswitch_key(
        &lwe_sk,
        &rlwe_sk,
        std,
        &mut encryption_generator,
        |x| mul * x,
        &Polynomial::from_container(vec),
    );
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    let msg = 5 as u64;
    let message = Plaintext((msg) << delta_log.0);

    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);
    let mut rlwe_out = GlweCiphertext::allocate(
        0_u64,
        pksk.output_polynomial_size(),
        pksk.output_glwe_key_dimension().to_glwe_size(),
    );

    pksk.functional_keyswitch_ciphertext(&mut rlwe_out, &lwe_in);
    let mut decrypted_message = PlaintextList::allocate(0u64, PlaintextCount(polynomial_size.0));
    rlwe_sk.decrypt_glwe(&mut decrypted_message, &rlwe_out);

    let mut result = *decrypted_message.tensor.first();
    result = ((result as f64 / ((1 as u64) << delta_log.0) as f64).round()) as u64;

    assert_eq!(msg * mul, result)
}

// test the CBS with private functional ks
// follow by a VP
#[test]
pub fn circuit_bs_vertical_packing() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);

    let level_bsk = DecompositionLevelCount(4);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_cbs = DecompositionLevelCount(5);
    let base_log_cbs = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(7); //10?
    let base_log_pksk = DecompositionBaseLog(4); //2?

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
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
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    // creation of all the pfksk for the circuit bootstrapping
    let vec_pfksk = create_vec_pfksk(
        level_pksk,
        base_log_pksk,
        &rlwe_sk,
        &rlwe_sk,
        &lwe_sk_bs_output,
        std,
        &mut encryption_generator,
    );

    let delta_log = DeltaLog(60);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'
    let value: u64 = 5;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);
    let mut witness = 0;

    let mut vec_ggsw = vec![];
    for i in (0..64 - delta_log.0 - 1).rev() {
        for _ in 0..4 {
            let mut res = circuit_bootstrap(
                &fourier_bsk,
                &lwe_in,
                &mut buffers,
                level_cbs,
                base_log_cbs,
                delta_log,
                |x| (x & (1 << i)) >> i,
                &vec_pfksk,
            );
            witness = (witness << 1) + ((value & (1 << i)) >> i);
            let mut ggsw = FourierGgswCiphertext::allocate(
                Complex64::new(0., 0.),
                rlwe_sk.polynomial_size(),
                rlwe_sk.key_size().to_glwe_size(),
                level_cbs,
                base_log_cbs,
            );
            FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &mut res, &mut buffers);
            vec_ggsw.push(ggsw);
        }
    }
    let delta_log_cmux = 54;

    let mut lut = vec![];
    let mut tmp = 0;
    for i in 0..(1 << vec_ggsw.len()) {
        lut.push(((i as u64 + tmp) % (1 << 10)) << delta_log_cmux);
        if (i + 1) % (1 << 10) == 0 {
            tmp += 1;
        }
    }
    /*
    for i in 0..1 << vec_ggsw.len() {
        lut.push(((i as u64 + tmp) % (1 << 10)) << delta_log_cmux);
        if (i + 1) % (1 << 10) == 0 {
            tmp += 1;
        }
    }
     */

    let result = vertical_packing(lut, &vec_ggsw, &mut buffers);

    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result);
    let num_lut =
        (((decrypted_message.0 as f64) / (1u64 << (delta_log_cmux)) as f64).round()) as u64;

    witness = witness % (1 << 10) + (witness >> 10);
    //witness = witness % (1 << 10);
    assert_eq!(witness, num_lut);
}

// test the CBS with KS + External product
// check if it's work with computing an external product
#[test]
pub fn test_cbs_v2() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);

    let level_bsk = DecompositionLevelCount(3);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_cbs = DecompositionLevelCount(4);
    let base_log_cbs = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(7);
    let base_log_pksk = DecompositionBaseLog(4);

    let level_ext = DecompositionLevelCount(7);
    let base_log_ext = DecompositionBaseLog(4);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    //create RLWE and LWE secret key
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk: LweSecretKey<_, Vec<u64>> =
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
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

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

    let delta_log = DeltaLog(60);

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
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    //encryption of a LWE with the value 'message'
    let value: u64 = 5;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);
    let mut res = circuit_bootstrap_v1(
        &fourier_bsk,
        &lwe_in,
        &mut buffers,
        level_cbs,
        base_log_cbs,
        delta_log,
        |x| x,
        &vec_fourier_ggsw,
        &pksk,
    );

    for i in rlwe_sk.as_polynomial_list().polynomial_iter() {
        println!("RLWE secret key : \n{:?}", i);
    }
    let mut decrypted =
        PlaintextList::from_container(vec![
            0_u64;
            polynomial_size.0 * level_cbs.0 * (rlwe_dimension.0 + 1)
        ]);
    rlwe_sk.decrypt_glwe_list(&mut decrypted, &res.as_glwe_list());
    println!("\nGGSW decryption : ");
    for i in decrypted.sublist_iter(PlaintextCount(polynomial_size.0)) {
        println!("{:?}", i);
    }
    println!();

    let mut ggsw = FourierGgswCiphertext::allocate(
        Complex64::new(0., 0.),
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
        level_cbs,
        base_log_cbs,
    );
    FourierGgswCiphertext::fill_with_forward_fourier(&mut ggsw, &mut res, &mut buffers);

    // encryption of a RLWE with the value [? ,0 ,0 ...,0]
    let mut vec = vec![0_u64; rlwe_sk.polynomial_size().0];
    vec[0] = 3_u64 << delta_log.0;
    let list = PlaintextList::from_container(vec);
    let mut rlwe_in = GlweCiphertext::allocate(
        0u64,
        rlwe_sk.polynomial_size(),
        rlwe_dimension.to_glwe_size(),
    );
    rlwe_sk.encrypt_glwe(&mut rlwe_in, &list, std, &mut encryption_generator);

    // RLWE out for the external product
    let mut rlwe_out = GlweCiphertext::allocate(
        0_u64,
        rlwe_sk.polynomial_size(),
        rlwe_sk.key_size().to_glwe_size(),
    );

    ggsw.external_product(&mut rlwe_out, &rlwe_in, &mut buffers);

    // decrypted value of RLWEin
    let mut decrypted_input_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_input_ext_prod, &rlwe_in);
    let first_value_decrypted_input_ext_prod = decrypted_input_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    // decrypted value of RLWEout ( after external prod)
    let mut decrypted_ext_prod =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_ext_prod, &rlwe_out);
    let first_value_decrypted_ext_prod = decrypted_ext_prod
        .as_mut_polynomial()
        .tensor
        .into_container()[0];

    assert_eq!(
        ((first_value_decrypted_ext_prod as f64) / (1u64 << delta_log.0) as f64).round(),
        ((first_value_decrypted_input_ext_prod as f64) / (1u64 << delta_log.0) as f64).round()
            * value as f64
    );
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
    std: LogStandardDev,
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
            &lwe_key,
            &glwe_key,
            std,
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
        &lwe_key,
        &glwe_key,
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
