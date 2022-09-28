use concrete_core::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // We instantiate the engines needed for the computations.
    const UNSAFE_SECRET: u128 = 0;
    let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    let mut fft_engine = FftEngine::new(())?;

    // We set the parameters for the operations.
    let (lwe_dim, glwe_dim, poly_size) =
        (LweDimension(720), GlweDimension(1), PolynomialSize(2048));
    let (pbs_dec_lc, pbs_dec_bl) = (DecompositionLevelCount(1), DecompositionBaseLog(23));
    let (ks_dec_lc, ks_dec_bl) = (DecompositionLevelCount(5), DecompositionBaseLog(4));
    let lwe_noise = Variance(StandardDev(0.00000774783151517677815848).get_variance());
    let glwe_noise =
        Variance(StandardDev(0.00000000000000022148688116005568513645324585951).get_variance());
    let encode_shift = 59;

    // We generate the various keys.
    println!("Generating keys ...");
    let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    let glwe_sk: GlweSecretKey64 =
        default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    let bsk: LweBootstrapKey64 = default_engine
        .generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, pbs_dec_bl, pbs_dec_lc, glwe_noise)?;
    let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    let lwe_interm_sk: LweSecretKey64 =
        default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk)?;
    let ksk: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
        &lwe_interm_sk,
        &lwe_sk,
        ks_dec_lc,
        ks_dec_bl,
        lwe_noise,
    )?;

    // We generate the input plaintext and encrypt to a lwe.
    println!("Generating input ...");
    let input = 3_u64 << encode_shift;
    let plaintext = default_engine.create_plaintext_from(&input)?;
    let lwe_input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, lwe_noise)?;

    // We generate the lut plaintext and encrypt to a glwe (here a constant function is used).
    println!("Generating lut ...");
    let lut = vec![8_u64 << encode_shift; poly_size.0];
    let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    let acc = default_engine
        .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;

    // We perform the bootstrap.
    println!("Bootstrap ...");
    let mut lwe_bs_output =
        default_engine.zero_encrypt_lwe_ciphertext(&lwe_interm_sk, lwe_noise)?;
    fft_engine.discard_bootstrap_lwe_ciphertext(&mut lwe_bs_output, &lwe_input, &acc, &bsk)?;

    // We perform the keyswitch.
    println!("Keyswitch ...");
    let mut lwe_ks_output = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk, lwe_noise)?;
    default_engine.discard_keyswitch_lwe_ciphertext(&mut lwe_ks_output, &lwe_bs_output, &ksk)?;

    // We decrypt the output.
    println!("Decrypt ...");
    let output_plaintext = default_engine.decrypt_lwe_ciphertext(&lwe_sk, &lwe_ks_output)?;
    let output = default_engine.retrieve_plaintext(&output_plaintext)?;

    // We decode and round.
    let decoded = output >> (encode_shift - 1);
    let carry = decoded % 2;
    let decoded = ((decoded >> 1) + carry) % (1 << (64 - encode_shift));

    println!("Decoded value: {}", decoded);

    Ok(())
}
