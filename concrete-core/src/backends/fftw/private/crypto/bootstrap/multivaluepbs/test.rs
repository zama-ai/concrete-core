use crate::backends::core::private::crypto::bootstrap::multivaluepbs::{
    generate_fourier_polynomial_multivalue, generate_fourier_polynomial_multivalue_base,
    generate_polynomial_multivalue, generate_polynomial_multivalue_base,
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

// #[test]
// fn multivaluepbs_base() {
//     // define settings
//     //=========================================================
//     let polynomial_size = PolynomialSize(512);
//     let rlwe_dimension = GlweDimension(1);
//     let lwe_dimension = LweDimension(100);
//     let level = DecompositionLevelCount(4);
//     let base_log = DecompositionBaseLog(8);
//     let std = LogStandardDev::from_log_standard_dev(-30.);
//     let noise = LogStandardDev::from_log_standard_dev(-30.);
//
//     let modulus = 16_usize;
//     let base = 4_usize;
//
//     let delta = (1_u64 << 63) / modulus as u64;
//     //=========================================================
//
//     //Generators
//     //=========================================================
//     let mut rng = rand::thread_rng();
//     let mut secret_generator = SecretRandomGenerator::new(None);
//     let mut encryption_generator = EncryptionRandomGenerator::new(None);
//     //=========================================================
//
//     //Generate keys
//     //=========================================================
//     let mut rlwe_sk =
//         GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
//
//     //key before bootstrap, obtained after key switch
//     let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
//     //encryption key, obtained after bootstrap
//     let input_key = rlwe_sk.clone().into_lwe_secret_key();
//
//     // allocation and generation of the key in coef domain:
//     let mut coef_bsk = StandardBootstrapKey::allocate(
//         0 as u64,
//         rlwe_dimension.to_glwe_size(),
//         polynomial_size,
//         level,
//         base_log,
//         lwe_dimension,
//     );
//     coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);
//
//     // allocation for the bootstrapping key
//     let mut fourier_bsk = FourierBootstrapKey::allocate(
//         Complex64::new(0., 0.),
//         rlwe_dimension.to_glwe_size(),
//         polynomial_size,
//         level,
//         base_log,
//         lwe_dimension,
//     );
//
//     let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(),
// fourier_bsk.glwe_size());     fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);
//
//     let mut pksk = PackingKeyswitchKey::allocate(
//         0 as u64,
//         level,
//         base_log,
//         input_key.key_size(),
//         rlwe_dimension.to_glwe_size().to_glwe_dimension(),
//         polynomial_size,
//     );
//     pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);
//
//     let mut ksk = LweKeyswitchKey::allocate(
//         0 as u64,
//         level,
//         base_log,
//         input_key.key_size(),
//         lwe_sk.key_size(),
//     );
//
//     ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
//     //=========================================================
//
//     for _ in 0..30 {
//         //Generate accumulators
//         //=========================================================
//         let mut poly_acc = Vec::with_capacity(modulus);
//         for i in 0..base{
//             poly_acc.push( generate_polynomial_multivalue_base(|x| (i as u64 * x) % base as u64,
// modulus, base, polynomial_size));         }
//         //=========================================================
//
//         // println!("poly_acc = {:?} ", poly_acc);
//
//         //Generate lwe ctxts
//         //=========================================================
//         let clear_1 = rng.gen::<u64>() % base as u64;
//         let ptxt_1 = Plaintext(clear_1 * delta);
//         let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
//         input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
//
//         let mut selector =
//             LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
//
//         ksk.keyswitch_ciphertext(&mut selector, &lwe_in_1);
//         //=========================================================
//
//         let result = fourier_bsk.multivalue_programmable_bootstrap(
//             &selector,
//             modulus as u64,
//             poly_acc.as_slice(),
//             &mut buffers,
//             // &ksk,
//             // &rlwe_sk,
//             //     &lwe_sk
//         );
//
//         // decryption of ct_res
//         //=========================================================
//         for (i, res_i) in result.iter().enumerate() {
//             let mut result = Plaintext(0_u64);
//             input_key.decrypt_lwe(&mut result, res_i);
//
//             //The bit before the message
//             let rounding_bit = delta >> 1;
//
//             //compute the rounding bit
//             let rounding = (result.0 & rounding_bit) << 1;
//
//             let dec_res = ((result.0.wrapping_add(rounding)) / delta) % base as u64;
//             // println!(
//             //     "clear_1 = {}, decry = {}",
//             //     clear_1, dec_res
//             // );
//             assert_eq!((clear_1 * i as u64) % base as u64, dec_res);
//         }
//         //=========================================================
//
//         // assert
//         // assert_eq!(true, false);
//     }
// }

// #[test]
// fn multivaluepbs() {
//     // define settings
//     //=========================================================
//     let polynomial_size = PolynomialSize(512);
//     let rlwe_dimension = GlweDimension(1);
//     let lwe_dimension = LweDimension(100);
//     let level = DecompositionLevelCount(4);
//     let base_log = DecompositionBaseLog(8);
//     let std = LogStandardDev::from_log_standard_dev(-30.);
//     let noise = LogStandardDev::from_log_standard_dev(-30.);
//
//     let modulus = 16_usize;
//     // let base = 4_usize;
//
//     let delta = (1_u64 << 63) / modulus as u64;
//     //=========================================================
//
//     //Generators
//     //=========================================================
//     let mut rng = rand::thread_rng();
//     let mut secret_generator = SecretRandomGenerator::new(None);
//     let mut encryption_generator = EncryptionRandomGenerator::new(None);
//     //=========================================================
//
//     //Generate keys
//     //=========================================================
//     let mut rlwe_sk =
//         GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
//
//     //key before bootstrap, obtained after key switch
//     let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);
//     //encryption key, obtained after bootstrap
//     let input_key = rlwe_sk.clone().into_lwe_secret_key();
//
//     // allocation and generation of the key in coef domain:
//     let mut coef_bsk = StandardBootstrapKey::allocate(
//         0 as u64,
//         rlwe_dimension.to_glwe_size(),
//         polynomial_size,
//         level,
//         base_log,
//         lwe_dimension,
//     );
//     coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);
//
//     // allocation for the bootstrapping key
//     let mut fourier_bsk = FourierBootstrapKey::allocate(
//         Complex64::new(0., 0.),
//         rlwe_dimension.to_glwe_size(),
//         polynomial_size,
//         level,
//         base_log,
//         lwe_dimension,
//     );
//
//     let mut buffers = FourierBuffers::new(fourier_bsk.polynomial_size(),
// fourier_bsk.glwe_size());     fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);
//
//     let mut pksk = PackingKeyswitchKey::allocate(
//         0 as u64,
//         level,
//         base_log,
//         input_key.key_size(),
//         rlwe_dimension.to_glwe_size().to_glwe_dimension(),
//         polynomial_size,
//     );
//     pksk.fill_with_packing_keyswitch_key(&input_key, &rlwe_sk, noise, &mut encryption_generator);
//
//     let mut ksk = LweKeyswitchKey::allocate(
//         0 as u64,
//         level,
//         base_log,
//         input_key.key_size(),
//         lwe_sk.key_size(),
//     );
//
//     ksk.fill_with_keyswitch_key(&input_key, &lwe_sk, noise, &mut encryption_generator);
//     //=========================================================
//
//     for _ in 0..30 {
//         //Generate accumulators
//         //=========================================================
//         let mut poly_acc = Vec::with_capacity(modulus);
//         for i in 0..modulus{
//             poly_acc.push( generate_polynomial_multivalue(|x| (i as u64 * x) % modulus as u64,
// modulus, polynomial_size));         }
//         //=========================================================
//
//         // println!("poly_acc = {:?} ", poly_acc);
//
//         //Generate lwe ctxts
//         //=========================================================
//         let clear_1 = rng.gen::<u64>() % modulus as u64;
//         let ptxt_1 = Plaintext(clear_1 * delta);
//         let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
//         input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);
//
//         let mut selector =
//             LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());
//
//         ksk.keyswitch_ciphertext(&mut selector, &lwe_in_1);
//         //=========================================================
//
//         let result = fourier_bsk.multivalue_programmable_bootstrap(
//             &selector,
//             modulus as u64,
//             poly_acc.as_slice(),
//             &mut buffers,
//             // &ksk,
//             // &rlwe_sk,
//             //     &lwe_sk
//         );
//
//         // decryption of ct_res
//         //=========================================================
//         for (i, res_i) in result.iter().enumerate() {
//             let mut result = Plaintext(0_u64);
//             input_key.decrypt_lwe(&mut result, res_i);
//
//             //The bit before the message
//             let rounding_bit = delta >> 1;
//
//             //compute the rounding bit
//             let rounding = (result.0 & rounding_bit) << 1;
//
//             let dec_res = ((result.0.wrapping_add(rounding)) / delta);
//             // println!(
//             //     "clear_1 = {}, decry = {}",
//             //     clear_1, dec_res
//             // );
//             assert_eq!((clear_1 * i as u64) % modulus as u64, dec_res);
//         }
//         //=========================================================
//
//         // assert
//         // assert_eq!(true, false);
//     }
// }

#[test]
fn multivaluepbs() {
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
    // let base = 4_usize;

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

    for _ in 0..30 {
        //Generate accumulators
        //=========================================================
        let mut poly_acc = Vec::with_capacity(modulus);
        for i in 0..modulus {
            poly_acc.push(generate_fourier_polynomial_multivalue(
                |x| (i as u64 * x) % modulus as u64,
                modulus,
                polynomial_size,
            ));
        }
        //=========================================================

        // println!("poly_acc = {:?} ", poly_acc);

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % modulus as u64;
        let ptxt_1 = Plaintext(clear_1 * delta);
        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);

        let mut selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());

        ksk.keyswitch_ciphertext(&mut selector, &lwe_in_1);
        //=========================================================

        let result = fourier_bsk.multivalue_programmable_bootstrap(
            &selector,
            modulus as u64,
            poly_acc.as_slice(),
            &mut buffers,
            // &ksk,
            // &rlwe_sk,
            //     &lwe_sk
        );

        // decryption of ct_res
        //=========================================================
        for (i, res_i) in result.iter().enumerate() {
            let mut result = Plaintext(0_u64);
            input_key.decrypt_lwe(&mut result, res_i);

            //The bit before the message
            let rounding_bit = delta >> 1;

            //compute the rounding bit
            let rounding = (result.0 & rounding_bit) << 1;

            let dec_res = ((result.0.wrapping_add(rounding)) / delta);
            // println!(
            //     "clear_1 = {}, decry = {}",
            //     clear_1, dec_res
            // );
            assert_eq!((clear_1 * i as u64) % modulus as u64, dec_res);
        }
        //=========================================================

        // assert
        // assert_eq!(true, false);
    }
}

#[test]
fn multivaluepbs_base() {
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

    for _ in 0..30 {
        //Generate accumulators
        //=========================================================
        let mut poly_acc = Vec::with_capacity(base);
        for i in 0..base {
            poly_acc.push(generate_fourier_polynomial_multivalue_base(
                |x| (i as u64 * x) % base as u64,
                modulus,
                base,
                polynomial_size,
            ));
        }
        //=========================================================

        // println!("poly_acc = {:?} ", poly_acc);

        //Generate lwe ctxts
        //=========================================================
        let clear_1 = rng.gen::<u64>() % base as u64;
        let ptxt_1 = Plaintext(clear_1 * delta);
        let mut lwe_in_1 = LweCiphertext::allocate(0u64, input_key.key_size().to_lwe_size());
        input_key.encrypt_lwe(&mut lwe_in_1, &ptxt_1, std, &mut encryption_generator);

        let mut selector = LweCiphertext::allocate(0_u64, fourier_bsk.key_size().to_lwe_size());

        ksk.keyswitch_ciphertext(&mut selector, &lwe_in_1);
        //=========================================================

        let result = fourier_bsk.multivalue_programmable_bootstrap(
            &selector,
            modulus as u64,
            poly_acc.as_slice(),
            &mut buffers,
            // &ksk,
            // &rlwe_sk,
            //     &lwe_sk
        );

        // decryption of ct_res
        //=========================================================
        for (i, res_i) in result.iter().enumerate() {
            let mut result = Plaintext(0_u64);
            input_key.decrypt_lwe(&mut result, res_i);

            //The bit before the message
            let rounding_bit = delta >> 1;

            //compute the rounding bit
            let rounding = (result.0 & rounding_bit) << 1;

            let dec_res = ((result.0.wrapping_add(rounding)) / delta) % base as u64;
            // println!(
            //     "clear_1 = {}, decry = {}",
            //     clear_1, dec_res
            // );
            assert_eq!((clear_1 * i as u64) % base as u64, dec_res);
        }
        //=========================================================

        // assert
        // assert_eq!(true, false);
    }
}
