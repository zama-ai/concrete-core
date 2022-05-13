use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey, FourierBuffers, StandardBootstrapKey,
};
use crate::backends::core::private::crypto::circuit_bootstrap::DeltaLog;
use crate::backends::core::private::crypto::encoding::{Plaintext, PlaintextList};
use crate::backends::core::private::crypto::ggsw::{FourierGgswCiphertext, StandardGgswCiphertext};
use crate::backends::core::private::crypto::glwe::{
    FunctionalPackingKeyswitchKey, GlweCiphertext, PackingKeyswitchKey,
};
use crate::backends::core::private::crypto::lwe::LweCiphertext;
use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::backends::core::private::crypto::vertical_packing::{
    blind_rotate, cmux_tree, cmux_tree_memory_optimized, vertical_packing, vertical_packing_cbs_v0,
    vertical_packing_cbs_v1,
};
use crate::backends::core::private::math::fft::Complex64;
use crate::backends::core::private::math::polynomial::Polynomial;
use crate::backends::core::private::math::tensor::{AsMutTensor, AsRefSlice, AsRefTensor};
use crate::backends::core::private::math::torus::UnsignedTorus;
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};

#[test]
pub fn test_cmux_tree() {
    // define settings
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(6);
    let nb_ggsw = 10;
    let delta_log = 60;

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let mut buffers = FourierBuffers::new(polynomial_size, rlwe_dimension.to_glwe_size());

    //creation of the 'big' lut
    //lut = [[0...0][1...1][2...2] ...] where [x...X] is a lut
    let mut lut = vec![0_u64; (1 << nb_ggsw) * polynomial_size.0];
    for i in 0..(1 << nb_ggsw) {
        for j in 0..polynomial_size.0 {
            lut[j + i * polynomial_size.0] = (i as u64 % (1 << (64 - delta_log))) << delta_log
        }
    }

    let mut value = 0b1111010111;
    let witness = value;
    //bit decomposition of the value
    let mut vec_message = vec![Plaintext(0); nb_ggsw];
    for i in (0..nb_ggsw).rev() {
        vec_message[i] = Plaintext(value & 1);
        value = value >> 1;
    }
    // bit decomposition are store in fourier ggsw which a store in this vector
    let mut vec_ggsw = vec![];
    for i in 0..nb_ggsw {
        let mut ggsw = StandardGgswCiphertext::allocate(
            0_u64,
            polynomial_size,
            rlwe_dimension.to_glwe_size(),
            level,
            base_log,
        );
        rlwe_sk.encrypt_constant_ggsw(&mut ggsw, &vec_message[i], std, &mut encryption_generator);
        let mut fourier_ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            rlwe_sk.polynomial_size(),
            rlwe_sk.key_size().to_glwe_size(),
            level,
            base_log,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(
            &mut fourier_ggsw,
            &mut ggsw,
            &mut buffers,
        );
        vec_ggsw.push(fourier_ggsw);
    }

    let result = cmux_tree_memory_optimized(lut.clone(), &vec_ggsw, &mut buffers, rlwe_dimension);
    println!("{:?}", result);
    let mut decrypted_result =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_result, &result);
    let lut_number =
        ((*decrypted_result.tensor.first() as f64) / (1u64 << delta_log) as f64).round();

    println!("{:?}", decrypted_result);
    //the number of the lut must be equals to the value store in ggsw
    println!("result : {:?}", lut_number);
    println!("witness : {:?}", witness % (1 << (64 - delta_log)));
    println!("lut value  : {:?}", lut[witness as usize]);
    assert_eq!(lut_number as u64, witness % (1 << (64 - delta_log)))
}

#[test]
pub fn test_blind_rotate() {
    // define settings
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(6);
    let nb_ggsw = 9;

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let mut buffers = FourierBuffers::new(polynomial_size, rlwe_dimension.to_glwe_size());
    let delta_log = 60;
    let mut lut = vec![];
    // Trivial lut where the blind rotation must be equals at value
    for i in 0..1 << nb_ggsw {
        lut.append(&mut vec![
            i << delta_log;
            polynomial_size.0 / (1 << nb_ggsw)
        ])
    }

    let mut value = 5;
    let witness = value;
    //bit decomposition of the value
    let mut vec_message = vec![Plaintext(0); polynomial_size.0];
    for i in (0..nb_ggsw).rev() {
        vec_message[i] = Plaintext(value & 1);
        value = value >> 1;
    }
    let mut vec_ggsw = vec![];
    for i in 0..nb_ggsw {
        let mut ggsw = StandardGgswCiphertext::allocate(
            0_u64,
            polynomial_size,
            rlwe_dimension.to_glwe_size(),
            level,
            base_log,
        );
        rlwe_sk.encrypt_constant_ggsw(&mut ggsw, &vec_message[i], std, &mut encryption_generator);
        let mut fourier_ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            rlwe_sk.polynomial_size(),
            rlwe_sk.key_size().to_glwe_size(),
            level,
            base_log,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(
            &mut fourier_ggsw,
            &mut ggsw,
            &mut buffers,
        );
        vec_ggsw.push(fourier_ggsw);
    }
    let mut mask_and_body = vec![0_u64; polynomial_size.0];
    mask_and_body.append(&mut lut.to_vec());

    let mut rlwe_lut = GlweCiphertext::from_container(mask_and_body, polynomial_size);
    blind_rotate(&mut rlwe_lut, &vec_ggsw, &mut buffers);
    let mut decrypted_result =
        PlaintextList::from_container(vec![0_u64; rlwe_sk.polynomial_size().0]);
    rlwe_sk.decrypt_glwe(&mut decrypted_result, &rlwe_lut);
    let lut_value =
        ((*decrypted_result.tensor.first() as f64) / (1u64 << delta_log) as f64).round();
    assert_eq!(lut_value as u64, witness % (1 << nb_ggsw));
}

#[test]
pub fn test_vertical_packing() {
    // define settings
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    let polynomial_size = PolynomialSize(512);
    let rlwe_dimension = GlweDimension(1);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let level = DecompositionLevelCount(6);
    let base_log = DecompositionBaseLog(6);
    let total_ggsw = 13;

    // allocation and generation of the key in coef domain:
    let rlwe_sk: GlweSecretKey<_, Vec<u64>> =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let mut buffers = FourierBuffers::new(polynomial_size, rlwe_dimension.to_glwe_size());
    let delta_log_cmux = 50;
    let delta_log_br = 46;

    // Lut where i << delta_log_cmux is the number of the lut and j << delta_log_br is the position
    // in the lut
    let mut lut: Vec<u64> = vec![];
    let mut tmp = 0;
    for i in 0..(1 << total_ggsw) {
        if i % polynomial_size.0 as u64 == 0 {
            tmp += 1;
        }
        lut.push(((i << delta_log_cmux) + (tmp << delta_log_br)) % (1 << 60));
    }

    let mut value = polynomial_size.0 as u64 * 4 + 12;
    let witness = value;
    //bit decomposition of the value
    let mut vec_message = vec![Plaintext(0); total_ggsw];
    for i in (0..total_ggsw).rev() {
        vec_message[i] = Plaintext(value & 1);
        value = value >> 1;
    }
    let mut vec_ggsw = vec![];
    for i in 0..total_ggsw {
        let mut ggsw = StandardGgswCiphertext::allocate(
            0_u64,
            polynomial_size,
            rlwe_dimension.to_glwe_size(),
            level,
            base_log,
        );
        rlwe_sk.encrypt_constant_ggsw(&mut ggsw, &vec_message[i], std, &mut encryption_generator);
        let mut fourier_ggsw = FourierGgswCiphertext::allocate(
            Complex64::new(0., 0.),
            rlwe_sk.polynomial_size(),
            rlwe_sk.key_size().to_glwe_size(),
            level,
            base_log,
        );
        FourierGgswCiphertext::fill_with_forward_fourier(
            &mut fourier_ggsw,
            &mut ggsw,
            &mut buffers,
        );
        vec_ggsw.push(fourier_ggsw);
    }
    let result = vertical_packing(lut, &vec_ggsw, &mut buffers);
    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result);
    let lut_value = (((decrypted_message.0 as f64) / (1u64 << delta_log_cmux) as f64).round())
        as u64
        % polynomial_size.0 as u64;
    let nb_lut = ((decrypted_message.0 as f64) / (1u64 << delta_log_br) as f64).round() as u64
        % (1 << (delta_log_cmux - delta_log_br));
    assert_eq!(lut_value, witness % polynomial_size.0 as u64);
    assert_eq!(nb_lut, witness / polynomial_size.0 as u64 + 1);
}

// CBS + VP
// CBS with PFKSK
#[test]
pub fn circuit_bs_vertical_packing_v0() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);

    let level_bsk = DecompositionLevelCount(4);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_cbs = DecompositionLevelCount(3);
    let base_log_cbs = DecompositionBaseLog(5);

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
    let vec_fpksk = create_vec_pfksk(
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
    //encryption of a LWE with the value 'message'
    let value: u64 = 5;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    let delta_lut = DeltaLog(55);
    let mut lut = vec![];
    let mut tmp = 0;
    for i in 0..(1 << 11) {
        lut.push(((i as u64 + tmp) % (1 << 10)) << delta_lut.0);
        if (i + 1) % (1 << 10) == 0 {
            tmp += 1;
        }
    }
    let mut witness = 0;
    let mut vec_nb_bit_to_extract = vec![3_usize; 3];
    vec_nb_bit_to_extract.push(2);
    witness += (value & 0b111) << 8;
    witness += (value & 0b111) << 5;
    witness += (value & 0b111) << 2;
    witness += value & 0b11;
    let vec_delta_log = vec![delta_log; 4];
    let vec_lut = vec![lut.clone(); 2];
    let vec_lwe_in = vec![lwe_in; 4];
    let result = vertical_packing_cbs_v0(
        vec_lut,
        &mut buffers,
        &fourier_bsk,
        &vec_lwe_in,
        level_cbs,
        base_log_cbs,
        vec_delta_log,
        &vec_fpksk,
        vec_nb_bit_to_extract,
    );

    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result[0]);
    let num_lut = (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
    println!("{:?}", num_lut);

    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result[1]);
    let num_lut = (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
    assert_eq!(num_lut, lut[witness as usize] >> delta_lut.0);
}

// CBS + VP
// CBS with KSK + External prod
#[test]
pub fn circuit_bs_vertical_packing_v1() {
    // define settings
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(50);

    let level_bsk = DecompositionLevelCount(4);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_cbs = DecompositionLevelCount(5);
    let base_log_cbs = DecompositionBaseLog(4);

    let level_pksk = DecompositionLevelCount(8); //10?
    let base_log_pksk = DecompositionBaseLog(5); //2?

    let level_ext = DecompositionLevelCount(8);
    let base_log_ext = DecompositionBaseLog(5);

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
    //encryption of a LWE with the value 'message'
    let value: u64 = 5;
    let message = Plaintext((value) << delta_log.0);
    let mut lwe_in = LweCiphertext::allocate(0u64, lwe_dimension.to_lwe_size());
    lwe_sk.encrypt_lwe(&mut lwe_in, &message, std, &mut encryption_generator);

    let delta_lut = DeltaLog(54);
    let mut lut = vec![];
    let mut tmp = 0;
    for i in 0..(1 << 11) {
        lut.push(((i as u64 + tmp) % (1 << 10)) << delta_lut.0);
        if (i + 1) % (1 << 10) == 0 {
            tmp += 1;
        }
    }

    let mut witness = 0;
    let mut vec_nb_bit_to_extract = vec![3_usize; 3];
    vec_nb_bit_to_extract.push(2);
    witness += (value & 0b111) << 8;
    witness += (value & 0b111) << 5;
    witness += (value & 0b111) << 2;
    witness += value & 0b11;
    let vec_delta_log = vec![delta_log; 4];
    let vec_lut = vec![lut.clone(); 2];
    let vec_lwe_in = vec![lwe_in; 4];
    let result = vertical_packing_cbs_v1(
        vec_lut,
        &mut buffers,
        &fourier_bsk,
        &vec_lwe_in,
        level_cbs,
        base_log_cbs,
        vec_delta_log,
        vec_nb_bit_to_extract,
        &vec_fourier_ggsw,
        &pksk,
    );

    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result[0]);
    let num_lut = (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
    println!("{:?}", num_lut);

    let mut decrypted_message = Plaintext(0 as u64);
    let lwe_sk = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
    lwe_sk.decrypt_lwe(&mut decrypted_message, &result[1]);
    let num_lut = (((decrypted_message.0 as f64) / (1u64 << (delta_lut.0)) as f64).round()) as u64;
    println!("{:?}", num_lut);
    assert_eq!(num_lut, lut[witness as usize] >> delta_lut.0);
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
