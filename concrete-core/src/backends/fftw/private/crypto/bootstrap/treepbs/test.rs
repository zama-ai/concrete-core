use crate::backends::core::private::crypto::bootstrap::multivaluepbs::{
    generate_fourier_polynomial_three_variables, generate_fourier_polynomial_two_variables,
    generate_polynomial_multivalue, generate_polynomial_three_variables,
    generate_polynomial_two_variables,
};
use crate::backends::core::private::crypto::bootstrap::treepbs::{
    generate_accumulator_treepbs, generate_accumulator_treepbs_base,
};
use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
};
use crate::backends::core::private::crypto::encoding::{Plaintext, PlaintextList};
use crate::backends::core::private::crypto::glwe::{GlweCiphertext, PackingKeyswitchKey};
use crate::backends::core::private::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::backends::core::private::math::fft::{Complex64, FourierPolynomial};
use crate::backends::core::private::math::polynomial::Polynomial;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::numeric::CastInto;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    MonomialDegree, PlaintextCount, PolynomialSize,
};
use rand::Rng;

#[test]
fn treepbs() {
    // define settings
    //=========================================================
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(100);
    let level = DecompositionLevelCount(4);
    let base_log = DecompositionBaseLog(8);
    let std = LogStandardDev::from_log_standard_dev(-30.);
    let noise = LogStandardDev::from_log_standard_dev(-30.);

    let modulus = 16_usize;
    let base = 4_usize;

    let delta = (1_u64 << 63) / modulus as u64;
    //=========================================================

    //Generators
    //=========================================================
    let mut rng = rand::thread_rng();
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    //=========================================================

    //Generate keys
    //=========================================================
    let mut rlwe_sk =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);

    //key before bootstrap, obtained after key switch
    let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    //encryption key, obtained after bootstrap
    let input_key = rlwe_sk.clone().into_lwe_secret_key();

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

    let mut pksk = PackingKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        rlwe_dimension.to_glwe_size().to_glwe_dimension(),
        polynomial_size,
    );
    pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);

    let mut ksk = LweKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        lwe_sk.key_size(),
    );

    ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
    //=========================================================

    //Create the polynomial to multiply the accumulator with
    //=======================================================================
    let mut poly_block_redundancy = vec![0_u64; polynomial_size.0];

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus;

    //let block_size = box_size * base;
    let block_size = box_size * modulus;

    for block in poly_block_redundancy.chunks_exact_mut(block_size) {
        block[..box_size].fill(1);
    }

    // println!("poly_redundancy = {:?}", poly_block_redundancy);
    let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
    //=======================================================================

    for _ in 0..100 {
        //Generate accumulators
        //=========================================================

        let mut accumulators = Vec::with_capacity(modulus);
        for i in 0..modulus {
            let f = |x: u64| (i as u64 * x) % modulus as u64;
            accumulators.push(generate_accumulator_treepbs(f, modulus, polynomial_size));
        }

        // Create the accumulator
        //=========================================================

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % modulus as u64;
        let clear_2 = rng.gen::<u64>() % modulus as u64;

        let ptxt_1 = Plaintext(clear_1 * delta);
        let ptxt_2 = Plaintext(clear_2 * delta);

        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_in_2 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_out = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());

        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
        input_key.encrypt_lwe(&mut lwe_in_2, &ptxt_2, std, &mut encryption_generator);

        let vec_lwe_in = vec![lwe_in_1, lwe_in_2];

        let empty_selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector.clone(); vec_lwe_in.len()];
        ksk.vector_keyswitch(&mut selectors, &vec_lwe_in);

        let lwe_buffer =
            LweCiphertext::allocate(0_u64, fourier_bsk.output_lwe_dimension().to_lwe_size());
        let mut lwe_buffer_bootstrap = vec![lwe_buffer.clone(); accumulators.len()];
        //=========================================================

        fourier_bsk.treepbs(
            &pksk,
            &mut lwe_out,
            selectors.as_slice(),
            &mut lwe_buffer_bootstrap,
            &ksk,
            accumulators.as_mut_slice(),
            &mut buffers,
            modulus,
            // base,
            0,
            &poly_redundancy,
            // &rlwe_sk,
            // &lwe_sk,
        );

        // decryption of ct_res
        //=========================================================
        let mut result = Plaintext(0_u64);
        input_key.decrypt_lwe(&mut result, &lwe_out);

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (result.0 & rounding_bit) << 1;

        let dec_res = ((result.0.wrapping_add(rounding)) / delta) as u64;
        println!(
            "clear_1 = {}, clear_2 = {}, decry = {}",
            clear_1, clear_2, dec_res
        );
        //=========================================================

        // assert
        assert_eq!((clear_1 * clear_2) % modulus as u64, dec_res);
        // assert_eq!(true, false);
    }
}

#[test]
fn treepbs_base() {
    // define settings
    //=========================================================
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(100);
    let level = DecompositionLevelCount(4);
    let base_log = DecompositionBaseLog(8);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let noise = LogStandardDev::from_log_standard_dev(-60.);

    let modulus = 16_usize;
    let base = 4_usize;

    let delta = (1_u64 << 63) / modulus as u64;
    //=========================================================

    //Generators
    //=========================================================
    let mut rng = rand::thread_rng();
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    //=========================================================

    //Generate keys
    //=========================================================
    let mut rlwe_sk =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);

    //key before bootstrap, obtained after key switch
    let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    //encryption key, obtained after bootstrap
    let input_key = rlwe_sk.clone().into_lwe_secret_key();

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

    let mut pksk = PackingKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        rlwe_dimension.to_glwe_size().to_glwe_dimension(),
        polynomial_size,
    );
    pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);

    let mut ksk = LweKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        lwe_sk.key_size(),
    );

    ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
    //=========================================================

    //Create the polynomial to multiply the accumulator with
    //=======================================================================
    let mut poly_block_redundancy = vec![0_u64; polynomial_size.0];

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus;

    let block_size = box_size * base;
    // let block_size = box_size * modulus;

    for block in poly_block_redundancy.chunks_exact_mut(block_size) {
        block[..box_size].fill(1);
    }

    // println!("poly_redundancy = {:?}", poly_block_redundancy);
    let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
    //=======================================================================

    for _ in 0..100 {
        //Generate accumulators
        //=========================================================

        let mut accumulators = Vec::with_capacity(base);
        for i in 0..base {
            let f = |x: u64| (i as u64 * x) % base as u64;
            accumulators.push(generate_accumulator_treepbs_base(
                f,
                modulus,
                base,
                polynomial_size,
            ));
        }

        // Create the accumulator
        //=========================================================

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % base as u64;
        let clear_2 = rng.gen::<u64>() % base as u64;

        let ptxt_1 = Plaintext(clear_1 * delta);
        let ptxt_2 = Plaintext(clear_2 * delta);

        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_in_2 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_out = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());

        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
        input_key.encrypt_lwe(&mut lwe_in_2, &ptxt_2, std, &mut encryption_generator);

        let vec_lwe_in = vec![lwe_in_1, lwe_in_2];

        let empty_selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector.clone(); vec_lwe_in.len()];
        ksk.vector_keyswitch(&mut selectors, &vec_lwe_in);

        let lwe_buffer =
            LweCiphertext::allocate(0_u64, fourier_bsk.output_lwe_dimension().to_lwe_size());
        let mut lwe_buffer_bootstrap = vec![lwe_buffer.clone(); accumulators.len()];
        //=========================================================

        fourier_bsk.treepbs_base(
            &pksk,
            &mut lwe_out,
            selectors.as_slice(),
            &mut lwe_buffer_bootstrap,
            &ksk,
            accumulators.as_mut_slice(),
            &mut buffers,
            modulus,
            base,
            0,
            &poly_redundancy,
            // &rlwe_sk,
            // &input_key,
        );

        // decryption of ct_res
        //=========================================================
        let mut result = Plaintext(0_u64);
        input_key.decrypt_lwe(&mut result, &lwe_out);

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (result.0 & rounding_bit) << 1;

        let dec_res = ((result.0.wrapping_add(rounding)) / delta) as u64;
        println!(
            "clear_1 = {}, clear_2 = {}, decry = {}",
            clear_1, clear_2, dec_res
        );
        //=========================================================

        // assert
        assert_eq!((clear_1 * clear_2) % base as u64, dec_res);
        // assert_eq!(true, false);
    }
}

// #[test]
fn treepbs_with_multivalue() {
    // define settings
    //=========================================================
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(100);
    let level = DecompositionLevelCount(4);
    let base_log = DecompositionBaseLog(8);
    let std = LogStandardDev::from_log_standard_dev(-30.);
    let noise = LogStandardDev::from_log_standard_dev(-30.);

    let modulus = 16_usize;
    let base = 4_usize;

    let delta = (1_u64 << 63) / modulus as u64;
    //=========================================================

    //Generators
    //=========================================================
    let mut rng = rand::thread_rng();
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    //=========================================================

    //Generate keys
    //=========================================================
    let mut rlwe_sk =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);

    //key before bootstrap, obtained after key switch
    let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    //encryption key, obtained after bootstrap
    let input_key = rlwe_sk.clone().into_lwe_secret_key();

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

    let mut pksk = PackingKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        rlwe_dimension.to_glwe_size().to_glwe_dimension(),
        polynomial_size,
    );
    pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);

    let mut ksk = LweKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        lwe_sk.key_size(),
    );

    ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
    //=========================================================

    //Create the polynomial to multiply the accumulator with
    //=======================================================================
    let mut poly_block_redundancy = vec![0_u64; polynomial_size.0];

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus;

    //let block_size = box_size * base;
    let block_size = box_size * modulus;

    for block in poly_block_redundancy.chunks_exact_mut(block_size) {
        block[..box_size].fill(1);
    }

    // println!("poly_redundancy = {:?}", poly_block_redundancy);
    let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
    //=======================================================================

    for _ in 0..100 {
        //Generarte polynomial accumulators
        //=========================================================
        let f = |x: u64, y: u64| ((x + 3 * y) / 2) % modulus as u64;
        let mut poly_acc = Vec::with_capacity(modulus);
        generate_fourier_polynomial_two_variables(f, modulus, polynomial_size, &mut poly_acc);
        //=========================================================

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % modulus as u64;
        let clear_2 = rng.gen::<u64>() % modulus as u64;

        let ptxt_1 = Plaintext(clear_1 * delta);
        let ptxt_2 = Plaintext(clear_2 * delta);

        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_in_2 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_out = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());

        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
        input_key.encrypt_lwe(&mut lwe_in_2, &ptxt_2, std, &mut encryption_generator);

        let vec_lwe_in = vec![lwe_in_1, lwe_in_2];

        let empty_selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector.clone(); vec_lwe_in.len()];
        ksk.vector_keyswitch(&mut selectors, &vec_lwe_in);
        //=========================================================

        fourier_bsk.treepbs_with_multivalue(
            &pksk,
            &mut lwe_out,
            &selectors,
            &ksk,
            &mut buffers,
            modulus as u64,
            0,
            &poly_redundancy,
            // &rlwe_sk,
            // &lwe_sk,
            &poly_acc,
        );

        // decryption of ct_res
        //=========================================================
        let mut result = Plaintext(0_u64);
        input_key.decrypt_lwe(&mut result, &lwe_out);

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (result.0 & rounding_bit) << 1;

        let dec_res = ((result.0.wrapping_add(rounding)) / delta);
        // println!(
        //     "clear_1 = {}, clear_2 = {}, decry = {}",
        //     clear_1, clear_2, dec_res
        // );
        //=========================================================

        // assert
        assert_eq!(((clear_1 + 3 * clear_2) / 2) % modulus as u64, dec_res);
        // assert_eq!(true, false);
    }
}

#[test]
fn treepbs_with_multivalue_three() {
    // define settings
    //=========================================================
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(10);
    let level = DecompositionLevelCount(8);
    let base_log = DecompositionBaseLog(8);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let noise = LogStandardDev::from_log_standard_dev(-60.);

    let modulus = 16_usize;
    let base = 4_u64;

    let delta = (1_u64 << 63) / modulus as u64;
    //=========================================================

    //Generators
    //=========================================================
    let mut rng = rand::thread_rng();
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    //=========================================================

    //Generate keys
    //=========================================================
    let mut rlwe_sk =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);

    //key before bootstrap, obtained after key switch
    let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
    //encryption key, obtained after bootstrap
    let input_key = rlwe_sk.clone().into_lwe_secret_key();

    // allocation and generation of the key in coef domain:
    let mut coef_bsk = StandardBootstrapKey::allocate(
        0 as u64,
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        rlwe_dimension.to_glwe_size(),
        polynomial_size,
        level,
        base_log,
        lwe_dimension,
    );

    let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
    fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

    let mut pksk = PackingKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        rlwe_dimension.to_glwe_size().to_glwe_dimension(),
        polynomial_size,
    );
    pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);

    let mut ksk = LweKeyswitchKey::allocate(
        0 as u64,
        level,
        base_log,
        input_key.key_size(),
        lwe_sk.key_size(),
    );

    ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
    //=========================================================

    //Create the polynomial to multiply the accumulator with
    //=======================================================================
    let mut poly_block_redundancy = vec![0_u64; polynomial_size.0];

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus;

    //let block_size = box_size * base;
    let block_size = box_size * modulus;

    for block in poly_block_redundancy.chunks_exact_mut(block_size) {
        block[..box_size].fill(1);
    }

    // println!("poly_redundancy = {:?}", poly_block_redundancy);
    let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
    //=======================================================================

    for _ in 0..10 {
        //Generarte polynomial accumulators
        //=========================================================
        let f = |x: u64, y: u64, z: u64| {
            (x + base * y + base * base * z) * (x + base * y + base * base * z) % modulus as u64
        };
        let capacity = modulus * modulus;
        let mut poly_acc = Vec::with_capacity(capacity);
        generate_fourier_polynomial_three_variables(f, modulus, polynomial_size, &mut poly_acc);
        // println!("poly = {:?}", poly_acc);
        //=========================================================

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % base as u64;
        let clear_2 = rng.gen::<u64>() % base as u64;
        let clear_3 = rng.gen::<u64>() % base as u64;

        let ptxt_1 = Plaintext(clear_1 * delta);
        let ptxt_2 = Plaintext(clear_2 * delta);
        let ptxt_3 = Plaintext(clear_3 * delta);

        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_in_2 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        let mut lwe_in_3 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());

        let mut lwe_out = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());

        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
        input_key.encrypt_lwe(&mut lwe_in_2, &ptxt_2, std, &mut encryption_generator);
        input_key.encrypt_lwe(&mut lwe_in_3, &ptxt_3, std, &mut encryption_generator);
        let mut vec_lwe_in = vec![lwe_in_1, lwe_in_2, lwe_in_3];

        let empty_selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector.clone(); vec_lwe_in.len()];
        ksk.vector_keyswitch(&mut selectors, &vec_lwe_in);
        //=========================================================

        fourier_bsk.treepbs_with_multivalue(
            &pksk,
            &mut lwe_out,
            &selectors,
            &ksk,
            &mut buffers,
            modulus as u64,
            0,
            &poly_redundancy,
            // &rlwe_sk,
            // &input_key,
            &poly_acc,
        );

        // decryption of ct_res
        //=========================================================
        let mut result = Plaintext(0_u64);
        input_key.decrypt_lwe(&mut result, &lwe_out);

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (result.0 & rounding_bit) << 1;

        let dec_res = ((result.0.wrapping_add(rounding)) / delta);
        // println!(
        //     "clear_1 = {}, clear_2 = {}, clear_3 = {}, decry = {}",
        //     clear_1, clear_2, clear_3, dec_res
        // );
        //=========================================================

        // assert
        assert_eq!(f(clear_1, clear_2, clear_3), dec_res);
        // assert_eq!(true, false);
    }
}
